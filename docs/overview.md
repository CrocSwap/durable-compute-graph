# DCG overview (draft for the alpha)

**Status: draft (2026-10-03), for owner review before it becomes the
README's opening.** Measured figures name their source; before
publication, each must be checked against the evidence it cites.

## What DCG is

DCG (Durable Compute Graph) runs computations that are too big for one
transaction on Fogo (an SVM chain). The chain stays the source of truth
either way. There are two modes:

- **Consensus mode.** The computation runs entirely on chain, split across
  as many transactions as it needs. DCG coordinates them:
  - durable state between transactions;
  - each step applied exactly once and in order;
  - views published at known points;
  - a sequencer that batches, pipelines and resends the transactions.

  Nothing has to be trusted or watched, because the chain executed
  everything.
- **Optimistic mode.** An executor runs the computation off chain and
  commits to every step. The result stands unless someone proves a step
  wrong. A dispute narrows to the first wrong step, and the chain executes
  only that one step to decide. An honest run costs a few transactions,
  however large the computation.

The long-term design mixes the modes per region of one graph. For example,
a small critical part runs on chain while a heavy part runs optimistically.
`explain()` reports the guarantee each part gets.

## Why use it

Use it when a result must be trusted on chain but does not fit in one
transaction:

- **Consensus mode suits work that must be fully on chain:** games and
  simulations, long state machines, and multi-step settlement. Doom's
  simulation and renderer run on DCG sessions on testnet (*measured*: about
  1.65 frames per second, about 140 transactions per frame; DCG
  `docs/plans/v2-roadmap.md`).
- **Optimistic mode suits work far too large to run on chain:** model
  inference, simulations, and data pipelines whose results contracts act
  on. Basanos uses DCG to make language-model outputs disputable.

Compared with the alternatives:

- **Trusting a server:** both modes remove the single trusted party.
- **ZK proofs:** both modes run ordinary integer programs with no circuits.
  Consensus mode pays for on-chain execution instead. Optimistic mode pays
  with a challenge window and needs an honest watcher.

## How it works

**The building block in both modes is a kernel:** a small, deterministic,
integer-exact function. DCG ships built-in kernels. An application adds its
own by compiling them into its program image, and the image's manifest
names them.

**Consensus mode: sessions.**
1. A session holds a stateful kernel's state in accounts.
2. Each transaction applies one transition: it reads the inputs, updates
   the state, and advances a cursor. Phase locks make a step apply once and
   in order. A duplicated or failed transaction cannot skip ahead or
   corrupt state.
3. The sequencer submits the transactions, resends any that fail, and
   records progress in a journal, so a crash resumes where it stopped.
4. Views (for example a rendered frame) are published from the state for
   other programs and clients to read.

**Optimistic mode: runs and disputes.**
1. You describe the computation as a graph of kernel calls, in Python. DCG
   compiles it into a template: a fixed plan whose fingerprint is stored on
   chain.
2. An executor runs the plan off chain and builds a Merkle tree over every
   step. Each leaf records what the step read and what it produced. The
   executor posts the root and a bond.
3. Watchers rerun what they care about. If nobody disputes within the
   challenge window, the run is final, and the executor gets its bond back.
4. A disputer opens a dispute with a bond. The two sides walk down the tree
   together, following the first branch where they disagree, until they
   reach one step.
5. The chain checks one specific claim about that step:
   - an input does not match its producer's output;
   - the output is not what the kernel computes;
   - the step's shape does not match the plan.

   The loser forfeits its bond, and a convicted run is marked refuted.
6. Disputes, buffers and caches close, and their rent comes back. A settled
   run shrinks to a small permanent receipt that keeps its verdict.

## What users need to know

**Consensus mode:**
- **Throughput and fees are the limits:** every step is a real
  transaction, with the chain's per-transaction compute ceiling. Lanes let
  independent parts of a session advance in parallel: Doom on DCG ran
  1,000 frames at 3.81 frames per second on testnet with 3 lanes
  (*measured* 2026-10-05).
- **No watcher, no challenge window and no trusted template:** the chain
  executed everything.

**Optimistic mode:**
- What each mode guarantees, and how to check a template or session with
  `explain`: [`guarantees.md`](guarantees.md).
- **At least one honest, watching challenger:** a lie nobody challenges
  within the window stands. The alpha ships a watchtower service.
- **Responsiveness:** each party must act before its phase deadlines, and
  missing one loses the dispute. Windows must be sized for the data; a
  64 KiB witness took about 50 seconds to stage on testnet (*measured*
  2026-10-03, Basanos `out/runs/v21-image-b-2026-10-03/`).
- **A trusted template:** templates are compiled and sealed off chain.
  Trust whoever sealed it, or verify it yourself with the verify tool.
- **Kernels that agree with their reference:** the kernel kit checks that
  each custom kernel and its off-chain reference agree. If they disagree,
  honest parties can lose.
- **Not private and not instant:** challengers must be able to read the
  inputs and intermediate values, and finality waits for the window.

**Both modes:**
- **Exact integer arithmetic only:** floating-point models must be
  quantized into an integer-exact form first.
- **Faithful execution, not usefulness:** DCG shows a computation was done
  as stated, not that the computation is the right one.

**Alpha status:**
- Testnet only, and formats may change before beta.
- The optimistic dispute program, the template lifecycle and the closes,
  and sessions with lanes have each had independent reviews, with fixes
  re-reviewed. Sessions and the dispute program are also covered by
  run-level fuzzers.
- Python first; TypeScript later.
- Known limits are listed with each release.
