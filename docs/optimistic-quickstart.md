# Optimistic quickstart: trace a graph, catch a lie

In optimistic mode an executor runs your computation off chain and commits
to the result. Anyone can check it, and a wrong commitment is refuted on
chain by replaying one step. This guide runs the whole loop on your machine
in about three minutes:
- you trace a Python function into a plan;
- an executor commits two runs of it, one honest and one that lies;
- a watchtower checks both runs and convicts the lie;
- everything is settled and closed, and the rent comes back.

For consensus mode (sessions whose every step runs on chain), see
[`session-quickstart.md`](session-quickstart.md).

## 1. Set up

You need:
- Python 3.12 with this repository's `python/` package;
- the Solana CLI tools (`solana-test-validator`, `cargo build-sbf`).

```sh
cd python && uv sync && cd ..       # or: python -m venv, then pip install -e python
```

## 2. Start a local chain

```sh
dcg dev
```

`dcg dev` builds the alpha program image the first time (36 s measured;
later starts take about a second). It starts a local validator with the
program loaded at a fresh address, funds a payer, and prints an env file to
source. Leave it running, and in a second terminal:

```sh
source /private/tmp/dcg-dev-…/dcg-dev.env     # the path dcg dev printed
```

`dcg` is installed with the `python/` package; without installing, use
`PYTHONPATH=python python -m dcg dev`.
See [`dev-commands.md`](dev-commands.md) for the options.

## 3. Run the quickstart

```sh
PYTHONPATH=python python examples/optimistic-quickstart/quickstart.py
```

You will see output like this (measured 2026-10-05 on a local chain):

```text
v2.1 plan 'checksum': 5 steps in 2 blocks
  block 0: repeated 4 times, body 1 (sumchunk_i32), gate entry 0 port 1
  block 1: enumerated, 1 steps (head_i32)
  input 0: chunked, 256 bytes, chunks of 64 bytes
  output 0: 8 bytes
template CNxnyy36…
committed the honest run FX3o3Vht…
committed the lying run 3FmizLiD…
waiting for the watchtower and the executor (2-3 minutes locally, about 5 on testnet)...
  watchtower: the honest run matches its inputs
  watchtower: the lying run does not match; dispute opened
  watchtower: descending toward the first wrong step
  watchtower: claim sent (STEP)
  executor: the lying run is settled and closed
  executor: the honest run is settled and closed
the honest run: FINAL (accepted)
the lying run: REFUTED (the executor's bond was slashed)
done in 130 s, 21 transactions. The payer spent 6,254,800 lamports: 6,124,800 stay in the two run receipts (each run's permanent record), the rest is fees. ...
```

## 4. What happened

**The plan.** The traced function is:

```python
@v21.trace
def checksum(data: v21.Chunked(bytes=256, chunk=64)):
    acc = v21.reduce("sumchunk_i32", data)   # one step per 64-byte chunk
    v21.call("head_i32", acc)                # a step that reads the result
    return acc
```

Tracing turns it into a plan of five steps: four chunk steps, then one more.
The plan's fingerprint (its spec root) goes into a **template** on chain,
together with the windows and bonds. A template can serve any number of
runs.

**The commitment.** For each run, the executor computes every step and
commits one root. That root covers every step's inputs, outputs and state.
The run's inputs are committed only as digests. The executor posts a bond
(0.002 FOGO here). The lying executor corrupted the running sum at chunk 2,
then carried on consistently, so the final output looks plausible.

**The check.** The watchtower gets each run's inputs from the application.
Here that is a dictionary in the same process; in a real application it is
whatever store you publish inputs to. It recomputes the root. The honest run
matches. The lying run does not, so the watchtower opens a dispute and posts
its own bond (0.001 FOGO).

**The descent.** The executor reveals the children of the committed tree,
and the watchtower picks the first child that differs from its own. A few
rounds later, the dispute is down to a single step: chunk 2.

**The ruling.** The watchtower sends a STEP claim. The program replays that
one step on chain from the committed inputs and compares the result with the
executor's committed output. They differ, so the program rules for the
challenger and marks the run REFUTED. A consumer reading the run sees that
at once.

**Settlement.** Settlement moves the bonds and closes the accounts:
- the watchtower gets its bond back plus the slasher share of the
  executor's bond (50% here);
- the run's payer gets the rest of the executor's bond;
- the honest run finalizes after its challenge window and returns its
  executor's bond;
- every dispute, buffer and cache closes, each run shrinks to a small
  receipt that records its status and root, and the template closes.

The rent of every closed account goes back to whoever paid it.

## 5. Make it yours

- **Change the graph.** Edit `checksum`. Straight-line calls of kernels,
  `v21.reduce` over chunked inputs, constants and lists all trace; Python
  `if` on traced values does not. The tracing design is
  [`design/tracing-v21-frontend.md`](design/tracing-v21-frontend.md).
- **Check a template before you use it.** Run
  `dcg explain template --rpc URL --template T --plan FILE:FUNCTION`. It
  reads the template from chain, checks your plan against it, and says what
  is and is not guaranteed. See [`guarantees.md`](guarantees.md).
- **Use your own kernel.** The built-in kernels cover sums and simple
  reductions. For anything else, write a kernel in Rust with a Python mirror,
  and build an application image that carries it:
  [`kernel-app.md`](kernel-app.md).
- **Run the services for real.** In production the executor service and the
  watchtower are separate long-running processes, usually run by different
  parties: [`services.md`](services.md).

## 6. On the shared testnet program

The alpha shared program on Fogo testnet is
`J9Eje75v3AgEUZZPJJTJNqKmVxiAjhRhQ7iKYBRo1Hi9`. It runs the reviewed alpha
image; `dcg verify` checks it ([`dev-commands.md`](dev-commands.md)).

```sh
export DCG_RPC_URL=https://testnet.fogo.io
export DCG_PROGRAM_ID=J9Eje75v3AgEUZZPJJTJNqKmVxiAjhRhQ7iKYBRo1Hi9
export DCG_PAYER_KEYPAIR=~/my-testnet-key.json    # funded with testnet FOGO; keep it 0600
PYTHONPATH=python python examples/optimistic-quickstart/quickstart.py
```

On testnet the quickstart uses longer windows: a 3,000-slot challenge window
(about 2 minutes) and 1,500-slot phases (about 1 minute). These leave room
for a service whose RPC calls take about 350 ms. The whole run takes about
five minutes.

## Costs

Measured on a local chain, 2026-10-05:
- **Transactions:** 21 for the two runs, including the template, the
  dispute, every close, and returning the parties' leftover funds to the
  payer.
- **Compute:** a STEP claim replays one step. The program's per-claim compute
  is bounded by the kernel's declared ceiling (`dcg explain` prints it).
- **Rent:** everything is refunded except the two run receipts, 3,062,400
  lamports each. A receipt is the run's permanent record (status and root).
- **Bonds:** the executor's bond returns unless the run is refuted, and the
  challenger's returns unless the challenger loses.

## Limits in the alpha

See [`release-terms.md`](release-terms.md) for the full list. The ones that
matter here:
- **Inputs:** they are committed as digests only, so a watchtower can check
  a run only if the application publishes its inputs. On-chain input posting
  is planned before any mainnet use.
- **Trusted plan:** the program trusts the template's spec root. Check the
  plan behind a template off chain (`dcg explain`) before relying on it.
- **Watchers must run:** a lie is refuted only if someone challenges it
  inside the challenge window.
