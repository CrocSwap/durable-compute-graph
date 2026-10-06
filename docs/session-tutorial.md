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

Copy the template application to the top of your DCG checkout:

```sh
cp -r examples/session-app my-app
cd my-app
```

Then edit these files:
- **`Cargo.toml`:**
  - The `dcg-program` path and the `[patch.crates-io] curve25519-dalek`
    path are relative to `examples/session-app`. For `my-app` at the
    checkout's top, change `../../crates/` to `../crates/` in both.
  - Rename the package if you like (`name = "my-app"`). `build.sh` names the
    image after it (`out/my_app.so`).
  - In your own repository, depend on DCG by git revision instead, and point
    the patch at that revision's `crates/dcg-program/vendor`:

    ```toml
    dcg-program = { git = "<DCG repository URL>", rev = "<commit>", default-features = false,
                    features = ["no-entrypoint", "revision-8"] }
    ```
- **`src/bin/tally-conform.rs`:** if you renamed the package, change
  `use dcg_session_app::TALLY;` to your crate name with underscores
  (`use my_app::TALLY;`). Rename the `[[bin]]` in `Cargo.toml` too if you
  like.

`build.sh` finds DCG's Python package through the checkout's git top level,
so it needs no edit.

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

**Cost:** one host build (80 to 185 s from cold on an M-series Mac, measured).

## 4. Build the program

```sh
./build.sh out                  # with DCG's Python environment active
```

This runs `cargo build-sbf` and writes `out/<package>.so` (for the
template, `out/dcg_session_app.so`) and a receipt with its sha256 and the DCG runtime version it embeds. The receipt
step runs `python3`; set `PYTHON=` to another interpreter if `python3` does
not have DCG's packages.

The host build prints many warnings from `dcg-program` (unused imports in
code your program does not link); they are harmless.

**Cost:** one SBF build (128 s from cold, measured 2026-10-05). The image is
about 376 KB.

## 5. Run a first session

```sh
python quickstart.py out/dcg_session_app.so
```

It starts a local validator with your program at a fresh address, opens a
session, writes four inputs (one of them a rejected 0), advances, reads the
state, checks it against the mirror, and closes the session.

**Cost (measured, local):** 11 to 13 s in all. The open creates the session,
its input stream, and one account per state span (three accounts for the
tally). Their rent comes back at close. The ledger directory is removed at
the end; pass `--keep` to keep it.

## 6. Run a long session

```sh
python long_session.py out/dcg_session_app.so --steps 2000     # about 250 transactions
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
{"step": "open", "session": "…", "accounts": 3, "rent_lamports": 27728640}
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
- **Describe your kernel to the session** in `quickstart.py`'s
  `TALLY_SESSION`. Its keys:

  | Key | Value |
  |---|---|
  | `id` | the kernel id: UTF-8 text of 1 to 16 bytes, as in `KernelDecl::new` |
  | `semantic_version`, `abi_version` | as in `KernelDecl::new` |
  | `mode` | `{"id": 0x434F4E53, "version": 3}` (consensus v3) |
  | `schema` | `{"id": <your STATE_SCHEMA id>, "version": 1}` |
  | `input_width` | bytes per input, 1 to 8 |
  | `state_spans` | the state's span lengths, 1 to 8 spans, summing to your declared state size |
  | `input_codec` | `"u8"` (inputs are integers 0 to 255) or `"bytes"` (inputs are `input_width` bytes) |
  | `state_codec` | `"bytes"`, or `"counter-u64-pair"` for two u64s |
  | `rejects_input` | `true` if the manifest declares `.rejects_input()` |
  | `stream_root` | optional: 32 bytes as hex; the default is fine |
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
