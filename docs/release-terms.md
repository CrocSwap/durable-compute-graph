# DCG alpha: release terms

**Status:** published 2026-10-05 (alpha plan R5, exit criterion 6); owner review pending, edits follow as changelog entries.

## What this release is

DCG alpha is research software for verifiable computation on Fogo **testnet**.
It has two modes:
- **optimistic:** v2.1 disputes with LX1 checkpointed machines, on the shared
  alpha program;
- **consensus:** stateful sessions, embedded in your own program.

## Use

- **Testnet only.** Do not deploy DCG to mainnet, and do not use it to hold or
  move anything of value. Bonds, pots and rent in the alpha are testnet
  tokens.
- **The shared alpha program** is
  `J9Eje75v3AgEUZZPJJTJNqKmVxiAjhRhQ7iKYBRo1Hi9` on Fogo testnet. Its image
  hash and build are published in `docs/hello-graph.md`; check them with
  `dcg verify`. It may be upgraded in place. An upgrade that changes account
  layouts is announced, and runs created before it must be settled first.
- **License:** GPL-3.0-only (see `LICENSE`). The license may change before a
  stable release; any change is announced here and in the changelog.

## Formats and compatibility

- **Formats may change before beta.** This covers instruction encodings,
  account layouts, hashes and domains, receipts, and the Python client's API.
- Every breaking change is listed in `CHANGELOG.md`, with what changed, who is
  affected, and how to migrate.
- Each program image carries its runtime version
  (`dcg-runtime/1 <version> …`), so you can tell which version a deployed
  program embeds and whether an advisory applies to it.

## What is guaranteed, and what is not

**Optimistic mode** (`dcg explain template` prints this for a given
template):

- **What it guarantees:** a wrong commitment is refuted if an honest watcher
  challenges it inside the challenge window. The program then replays the
  first disputed step and rules.
- **It depends on:**
  - **Input availability.** Inputs are committed as digests only. A watcher
    can check a run only if the application makes its inputs available.
    On-chain input posting is planned before any mainnet use.
  - **The plan behind a template.** The spec root is trusted; check the plan
    off chain.
  - **The live image.** Application kernels resolve against the image that
    is live when a dispute is ruled. Do not change a kernel while runs that
    use it are live.
- **Known gaps:**
  - LOG state is reserved and not supported: the plan builder refuses it,
    and a lie at a LOG-state step is ruled moot, not convicted, so admitters
    must refuse LOG-state templates (use LX1 checkpoints for large state);
  - the v1 watchtower does not check LX1 runs.
- **Windows:** the program's minimum windows (750 slots) are short for a
  watcher far from its RPC node. `dcg explain` warns, and `docs/services.md`
  gives measured sizing guidance.

**Consensus mode:**

- **What it guarantees:** the program executes every input of a session
  itself, in order. There are no disputes, bonds or windows.
- **Known limits:**
  - anyone may close a halted session's children (L3 in the sessions review);
  - a ring stream keeps only its last lap of inputs, so your application must
    keep its own input log.

**Services and client:**
- The executor service, the watchtower and the sequencer are reference
  implementations. Their known limits are listed in `docs/services.md` and
  `docs/sequencer.md`.

**Not guaranteed at all:**
- availability or uptime of the shared program or of any RPC node;
- fees, or how fast transactions land;
- that alpha formats will be supported after beta.

## Security

Report vulnerabilities privately as described in `SECURITY.md`
(security@crocodilelabs.io); the disclosure window is 90 days.
