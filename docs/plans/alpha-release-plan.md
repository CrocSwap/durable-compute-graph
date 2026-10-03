# DCG alpha release plan

**Status: draft for owner review (2026-10-03).** Durations are **estimates**.
Nothing here is measured yet unless it says so.

## What the alpha is

The alpha is the first release that people outside the project can use on
Fogo testnet. They write a computation, run it on the shared DCG program, and
get optimistic disputes, with a clear statement of what is guaranteed and
what is not.

It is not a mainnet release. It also does not depend on Basanos moving its
documents to v2.1. Basanos's own mainnet switchover runs separately and in
parallel; it is useful evidence, but it does not gate the alpha.

## Proposed surface (owner decision)

| In the alpha | Out of the alpha |
|---|---|
| **v2.1 optimistic disputes (tag 227):** templates, runs, first-divergence descent, the claims, chunked kernels, committed constants, list inputs, application kernels by manifest, rent reclaim | **The v2.0 trace path (tags 208–226):** superseded by v2.1. It stays behind its feature flag and is not documented for users. |
| **Stateful sessions** (what Doom runs on) | **Sampling, Freivalds and ZK modes:** not started |
| **The Python tracing frontend, client and sequencer** | **LOG-state templates:** refused until LOG is on chain (re-review condition) |
| **`explain()` for v2.1 templates** | **TypeScript:** a thin layer after the alpha |

## Readiness work

**R1. Finish hardening v2.1.**
- List inputs and template closes land: in progress, and template closes get their own review.
- Follow-ups A and B from the 10-03 re-review: narrow the LOG neutrality; implement the design's additive load extension, counted only while disputes wait on the executor.
- The run-level dispute fuzzer: several disputes per run, random interleavings, invariants checked after every step.

**R2. Review the whole surface.** Only tag 227 has had an independent review.
- Stateful sessions, admission, the template lifecycle, and every other handler the shared program exposes each get an independent adversarial review (Basanos project rule 10).
- That includes the staging-buffer question from finding F10: does any handler accept an account by owner and magic alone?

**R3. Put the reviewed image on the shared testnet program.** It runs `7b04f8d5` today, which is pre-review.
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

**E5. Named errors.** A table in the client that maps every tag-227 error code to its name and meaning: `0x660d` becomes "phase deadline passed".

**E6. Developer commands.**
- `dcg dev`: a local validator, the program deployed, a funded payer.
- `dcg build`: a reproducible program image with its receipt.
- Today these take a pinned SDK path, wrapper environment variables and the Basanos runbook's deploy tools.

**E7. Docs.**
- Getting started for v2.1, replacing today's v2.0-era guide.
- A dispute walkthrough (a lie, the descent, the ruling, settlement, rent back).
- "Your first custom kernel", using E2.
- A guarantees page built on `explain()`.

**E8. `explain()` for v2.1 templates:** modes, kernels and their STEP mode, the dispute path, windows, bonds, and the open limits.

## Order of work (estimated)

| Phase | Work | Estimate |
|---|---|---|
| 1 | R1 (hardening), E5 (named errors), E4 (lifecycle in the client) | about 1 week |
| 2 | E1 (v2.1 lowering), E2 (kernel kit), E8 (`explain()`), R4 (repo boundary) | about 1–2 weeks |
| 3 | E3 (executor and watchtower), R2 (reviews of the whole surface) | about 1–2 weeks, partly parallel with phase 2 |
| 4 | R3 (shared program upgrade), E6 (`dcg dev`, `dcg build`), E7 (docs), R5 (terms) | about 1 week |

**Estimated total: about 4–6 weeks** at the current pace, with phases 2 and 3 overlapping. Doom lanes (milestone 5) are not on this path. If they land in time, Doom ships at 3 frames/s as the alpha's showcase; if not, it ships as the slower demo it is today.

## Exit criteria

The alpha ships when all of these hold:

1. **Independent reviews:** every handler in the alpha surface has one, and every finding is fixed or written up as a known limit.
2. **Fuzzer:** it runs clean, natively and on SBF, over the agreed number of interleavings.
3. **Public program:** the shared testnet program runs the reviewed image, and the hash is published.
4. **A newcomer test,** with no help from the authors. Starting from the docs, someone who did not build DCG:
   - traces a v2.1 graph;
   - runs it on the shared program;
   - watches the watchtower convict a planted lie;
   - gets their rent back.
5. **A custom kernel** passes the kernel kit's conformance harness and wins an honest dispute on testnet.
6. **Release terms** are published.

## Decisions for the owner

1. The alpha surface (the table above): in particular, leave out the v2.0 trace path, and include stateful sessions.
2. The license for the alpha (GPL-3, or a change before first release).
3. Whether Doom at today's speed is an acceptable alpha showcase, or lanes become a gate.
4. Who answers the security contact, and how breaking changes are announced.
