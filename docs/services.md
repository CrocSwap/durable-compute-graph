# Executor service and watchtower

Optimistic mode is safe only if two things always happen:
- the executor answers its disputes before each phase deadline;
- someone checks committed runs and challenges a wrong one inside the
  challenge window.

`dcg.services` provides both, as long-running Python loops. Alpha plan item
E3; the design is `docs/design/executor-watchtower-v1.md`.

## Executor service

```python
from dcg.services.executor import ExecutorService, Plan

service = ExecutorService(client, executor_key, "executor.json",
                          {str(template): Plan(spec, plan_id, depth)})
service.add_run(run, template, run_id, values)   # before committing (write ahead)
client.commit(run, template, root, executor_key)
while True:
    service.tick()                               # at least every phase_window / 4
    time.sleep(1)
```

Each tick does three things, in this order:

1. **Answers its runs' open disputes, soonest deadline first, across all
   runs.** One dispute's failure does not stop the others.
   - **Descents:** it reveals nodes, then the leaf. A list leaf, or one
     over 700 bytes, is staged first. Staging is resumable: a buffer left
     by an interrupted attempt is reused, and so is one created by the
     challenger, which the program allows.
   - **LX1:** it sends midpoint roots, then opens the terminal transition.
     Pass `Plan(lx=...)`; `ExecutionAnswerer` wraps an `lx.Execution` and is
     checked against the committed checkpoints before it answers.
   - **Timeouts:** it claims a timeout when the challenger is late.
2. **Finds new disputes** from its runs' transactions.
   - The number of transactions read per tick is bounded.
   - Only transactions that invoke the program count, so anyone can name
     the run without slowing the service.
   - Accounts loaded through lookup tables are included.
   - The cursor never skips a transaction that could not be read yet.
3. **Settles** where a step is possible. It uses the accounts it already
   knows, not a scan of the run's whole history.

A tick that runs past its budget is logged (`slow_tick`).

The service recomputes each descent commitment from the journaled inputs.
It refuses to answer if the result is not the root on chain.

## Watchtower

```python
from dcg.services.watchtower import Watched, Watchtower

def inputs(run, external_id, ref):     # the application's input source
    return my_store.get(run, external_id)

tower = Watchtower(client, challenger_key, "watchtower.json",
                   [Watched(template, spec, plan_id, inputs, depth)])
while True:
    tower.tick()
    time.sleep(1)
```

**At start-up** it checks each watched plan against its template on chain:
depth, step and output counts, spec root and plan id. A wrong plan would
make it challenge honest runs.

Each tick does three things, in this order:

1. **Plays its own disputes, soonest deadline first.**
   - It picks the first child that differs from H.
   - At the leaf it builds the claim from H plus the nodes the executor
     revealed on chain (the committed view). It checks the claim with the
     local referee in the program's mode before sending, and withholds a
     claim the program would not uphold. On a LOG-state step the program
     rules a STEP or STATE claim moot; such a run is not convicted, which is
     a known gap.
   - It reads list element refs from the executor's buffer only for a leaf
     with list inputs, and only if the buffer holds that same leaf.
   - It claims a timeout when the executor misses a deadline.
   - It settles after the ruling: advance, pay the pot, close, and get the
     bond and rent back.
2. **Checks newly committed runs inside their window.** It fetches the
   inputs from the application's source, checks them against the run's
   refs, computes H and compares it with the committed root. On a mismatch
   it opens a dispute with a fresh nonce. The open and its checked inputs
   are journaled before it is sent.
3. **Finds new runs** of the watched templates, with the same bounded
   discovery as the executor.

**What a watchtower can check.** A watchtower checks a run only if the
application makes that run's inputs available to it. The alpha program
stores each input only as a digest; on-chain input posting is planned before
any mainnet use (owner, 2026-10-05). LX1 runs are not checked in v1. The
executor service does answer LX1 disputes.

**Restarts and lost confirmations.**
- The watchtower rebuilds a dispute from its moves on chain, not from its
  journal: reveals, cache answers and picks, only those on this dispute.
- It does this after a restart, and whenever its view does not match the
  chain, as after a move whose confirmation was lost.
- It never opens a second dispute for a run it has already journaled.

**Races.** Anyone may settle, and several watchtowers may challenge the same
run. A settlement step refused because another party acted first is re-read
and retried. A watchtower move refused because the dispute was ruled
meanwhile is reported as a race. Disputes opened after the lowest challenger
win are ruled moot, and their bonds return.

## Measured (local validator, 2026-10-05)

- **Setup:** `examples/services/e2e_local.py` runs the services as separate
  processes against the alpha image on `solana-test-validator`, at 8 ticks
  per slot (about 50 ms). There are two templates: the chunked checksum, and
  a plan with a 13-element list input.
- **Base run:**
  - the honest run finalized unchallenged;
  - a consistent state lie was ruled C (STEP claim);
  - a wrong input was ruled C (EDGE claim);
  - a silent executor lost by timeout;
  - a list-element lie was ruled C. Its list leaf was staged by the executor
    and read back by the watchtower;
  - everything closed (66 s).
- **Adversaries:** `--precreate --plant-buffer --drop-pick-confirm` ran
  together, with every lie ruled C:
  - `--precreate`: the challenger created the executor's buffer first, and
    the honest executor still staged its list leaf;
  - `--plant-buffer`: a guilty executor planted a fake list body in its own
    buffer, and the watchtower still claimed;
  - `--drop-pick-confirm`: a pick landed with its confirmation "lost", and
    the watchtower recovered from chain.
- **`--restart-watchtower`:** the watchtower was killed after its first pick
  and rebuilt from chain. Every lie was ruled C.
- **`--watchtowers 2`:** every lie was ruled C, and the later disputes were C
  or moot.
- **LX1:** `examples/services/e2e_lx_local.py`, plain and `--weighted` (whose
  openings carry constant reads):
  - a lying executor was ruled C;
  - against a lying challenger, the executor service's opening stood and the
    run was ruled E.
- **Offline:**
  - the watchtower's claims are byte-identical to the offline game (347
    chunked disputes and 5 list lies);
  - discovery and history reading are unit-tested against a fake RPC.

**Not yet measured:**
- a run on the testnet alpha program;
- many runs at once, and ticks under load;
- a run where the executor must stage a large non-list leaf;
- priority fees and multi-node sends, which are C2's sequencer work.
