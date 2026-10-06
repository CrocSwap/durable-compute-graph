# Tutorial: a multi-transaction state machine

This tutorial goes from an empty directory to a long session running in your
own program, with the cost of each step shown. It is alpha plan item C5. The
shorter [`session-quickstart.md`](session-quickstart.md) explains the same
pieces in more depth; this page is the path to follow.

In consensus mode every step of your state machine runs on chain, in your
own program, with DCG's runtime embedded in it. Nobody needs to watch it and
there is no challenge window: once a step lands, it is final.

The example is a tally: each input byte adds to a running sum and a count,
and the input 0 is rejected (consumed, with the state unchanged).

## 1. Start from the template

```sh
cp -r examples/session-app my-app
cd my-app
```

In `Cargo.toml`, rename the package and point `dcg-program` at a pinned
revision of this repository instead of the relative path:

```toml
dcg-program = { git = "https://…/durable-compute-graph", rev = "<commit>", default-features = false,
                features = ["no-entrypoint", "revision-8"] }
```

Keep the `[patch.crates-io] curve25519-dalek` entry, pointed at the same
revision's `crates/dcg-program/vendor`. DCG's pinned dependency set needs it.

**Cost:** none (local files).

## 2. Write the transition

`src/lib.rs` holds the kernel. Change three things for your own machine:
- **The manifest:** a name, versions, the input width, the state size and a
  compute ceiling per step, declared once with `KernelDecl`.
- **`initial_state_spans`:** the state a new session starts in.
- **`transition_spans_with_outcome`:** one step. Read the input and the
  state, write the new state, and return `Continue`, `HaltBefore`,
  `HaltAfter` or `Reject`. Return an error to refuse the whole advance.

The rules: deterministic, integer-only, and no reads beyond the input and
the state. [`session-quickstart.md`](session-quickstart.md) section 1 walks
through the tally's version.

**Cost:** none.

## 3. Mirror it in Python, and check the two agree

`mirror.py` is the same transition in Python. Clients use it to predict
state; the kernel kit checks it against the Rust kernel at every edge.

```sh
cargo build --features conform,no-entrypoint --bin tally-conform
PYTHONPATH=../python python -m dcg.kernel_kit check --bin target/debug/tally-conform mirror.py
# dcg-tally-v1 v1/1 (stateful): 221 cases, 0 disagreements (continue 128, init state 3, refused 67, reject 23)
```

Fix any disagreement before going on. A disagreement means a client would
predict a state the chain does not reach.

**Cost:** one host build (about 80 s from cold on an M-series Mac).

## 4. Build the program

```sh
PYTHON=$(which python) ./build.sh out
```

This runs `cargo build-sbf` and writes `out/dcg_session_app.so` and a
receipt with its sha256 and the DCG runtime version it embeds. `PYTHON` must
be a Python with this repository's `python/` package installed; the receipt
step uses it.

**Cost:** one SBF build (128 s from cold, measured 2026-10-05). The image is
about 376 KB.

## 5. Run a first session

```sh
PYTHONPATH=../python python quickstart.py out/dcg_session_app.so
```

It starts a local validator with your program at a fresh address, opens a
session, writes four inputs (one of them a rejected 0), advances, reads the
state, checks it against the mirror, and closes the session.

**Cost (measured, local):** 11 s in all. The open creates three accounts:
the session, its input stream and its state. Their rent comes back at close.

## 6. Run a long session

```sh
PYTHONPATH=../python python long_session.py out/dcg_session_app.so --steps 2000
```

`long_session.py` is the real shape of a consensus application:
- **A ring input stream,** so the session can run any number of steps. The
  writer stays at most 64 inputs ahead of the cursor.
- **Batches:** `Session.write_and_advance(batch)` writes 8 inputs and
  advances over them in one transaction. All of it applies, or none does.
- **The sequencer** sends each transaction, journals it, and resends it if
  it does not land. To show this, the example drops one send on purpose
  (`--drop-at`). Either a rebroadcast of the same bytes lands, or, once the
  dropped signature's blockhash has expired, the sequencer checks the
  session's state and signs the step again. Both happened in the measured
  runs; in both, every step applied exactly once.
- **At the end** it reads the state, checks it against the mirror, reads the
  session's info (cursor and rejections), and closes everything.

Output (measured 2026-10-05, local validator with 50 ms slots, 400 steps):

```text
{"step": "open", "session": "…", "rent_lamports": 27768640}
{"step": "result", "count": 399, "sum": …, "cursor": 400, "rejected": 1, "mirror_agrees": true, "expected_rejections": 1}
{"step": "dropped send", "send_number": 10, "resent_same_bytes": 2, "landed": true, …}
{"step": "compute", "median_units_per_8_step_transaction": 63726, …}
{"step": "close", "rent_returned_lamports": 27728640, "accounts_closed": 3, "net_cost_lamports": 565000}
{"step": "done", "ok": true, "steps": 400, "transactions": 58, "session_transactions": 54, "steps_per_second": 15.7, "fee_lamports_per_transaction": 9741, …}
```

**Costs:**

| Item | Measured (local validator, 2026-10-05) |
|---|---|
| Rent while the session is open | 27,728,640 lamports for the session, a 128-slot ring stream and the state; all of it is returned at close, to the session authority |
| Fees | about 10,000 lamports per transaction (two signatures: payer and authority) |
| Transactions | one per 8 steps, plus 8 to open and close (400 steps took 58) |
| Compute | 63,726 units per 8-step transaction (about 8,000 per tally step) |
| Speed | about 16 steps per second, one transaction confirmed at a time |
| A long run | 16,000 steps in 2,008 transactions, 1,113 s (14.5 steps/s); mirror agrees; rent all returned; fees 20,065,000 lamports (about 10,000 per transaction) |

## 7. Make it yours

- **Change the transition** (step 2), re-run the kernel kit (step 3), and
  rebuild (step 4).
- **Change the session's layout** in `quickstart.py`'s `TALLY_SESSION`: the
  input width and the state spans must match your manifest.
- **Check the guarantee** for a live session:
  `print(await session.explain(decl=MANIFEST))` ([`guarantees.md`](guarantees.md)).
- **Go faster:** the sequencer guide ([`sequencer.md`](sequencer.md))
  explains `OrderedLane`, which sends a chain of transactions without
  waiting for each one. That is how Doom reaches 3.81 frames per second on
  testnet.
- **Deploy to testnet:** deploy `out/dcg_session_app.so` at your own program
  address with `solana program deploy`. Run `dcg verify` to check the
  deployed image against your receipt, then point `SolanaRpcEndpoint` at the
  testnet RPC. The session code is unchanged. Deploying needs rent for the
  program's data account; `solana rent <bytes>` gives the amount.

## What this does not cover

- Views, lanes, resources and phased initialization through the Python
  `Session`. They are built and tested in Rust
  ([`stateful-workloads-v3.md`](stateful-workloads-v3.md)), and Doom drives
  them directly.
- Network throughput. The numbers above are from a local validator. On a
  remote testnet node, each confirmation round trip costs more; measure from
  the host you will run on.
