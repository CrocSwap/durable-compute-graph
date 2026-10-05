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
service.add_run(run, template, run_id, values)   # after init_run and commit
while True:
    service.tick()                               # at least every phase_window / 4
    time.sleep(1)
```

On each tick, for every run it committed, the service does the following:
- **Finds disputes.** It reads the run's new transactions to find disputes.
- **Answers descents.** For a STEP or OUT descent it reveals nodes, then the
  leaf. A leaf that is large, or has list inputs, is staged first.
- **Answers LX1 disputes.** It sends the midpoint roots, then opens the
  terminal transition. Pass `Plan(lx=...)` with an `LxAnswerer`;
  `ExecutionAnswerer` wraps an `lx.Execution`.
- **Claims timeouts.** If the challenger misses a deadline, the service
  claims the timeout.
- **Settles.** Once nothing is pending, it calls `settle_and_reclaim`. That
  finalizes the run after its window, closes everything and returns the rent.

The service recomputes each commitment from the journaled inputs. It refuses
to answer if the result is not the root on chain.

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

On each tick the watchtower does the following:

1. **Finds runs.** It reads the watched templates' new transactions to find
   their runs.
2. **Checks each committed run inside its window:**
   - it fetches the run's inputs from the application's source and checks
     them against the run's refs;
   - it computes H (its own honest execution of the plan) and compares it
     with the committed root.
3. **Opens a dispute** with a fresh nonce on a mismatch. The open is
   journaled before it is sent.
4. **Plays the dispute:**
   - it picks the first child that differs from H;
   - it claims at the leaf, building the claim from H plus the nodes the
     executor revealed on chain (the committed view);
   - it checks every claim with the local referee before sending, and
     withholds a claim the referee would rule against.
5. **Claims timeouts** when the executor misses a deadline.
6. **Settles:** advance, pay the pot, close, and get the bond and rent back.

**What a watchtower can check.** A watchtower checks a run only if the
application makes that run's inputs available to it. The alpha program
stores each input only as a digest; on-chain input posting is planned before
any mainnet use (owner, 2026-10-05). LX1 runs are not checked in v1. The
executor service does answer LX1 disputes.

**Restarts.** After a crash the watchtower rebuilds each of its disputes from
the dispute's own transactions on chain (every reveal and pick), not from its
journal. It never opens a second dispute for a run it has already
journaled.

**Races.** Anyone may settle, and several watchtowers may challenge the same
run. A move refused because another party acted first is re-read and retried,
or reported as a race. Disputes opened after the lowest challenger win are
ruled moot, and their bonds return.

## Measured (local validator, 2026-10-05)

- **Setup:** `examples/services/e2e_local.py` runs the services as separate
  processes against the alpha image on `solana-test-validator`, at 8 ticks per
  slot (about 50 ms).
- **Base run:**
  - the honest run finalized unchallenged;
  - a consistent state lie was ruled C on a STEP claim;
  - a wrong input was ruled C on an EDGE claim;
  - a silent executor lost by timeout;
  - everything closed (63 s).
- **`--restart-watchtower`:** the watchtower was killed after its first pick
  and restarted. It rebuilt three disputes from chain, and every one was
  ruled C.
- **`--watchtowers 2`:** both towers challenged every lie. The later
  disputes were ruled C or moot, with no errors.
- **LX1:** `examples/services/e2e_lx_local.py`, with the toy machine:
  - a lying executor was ruled C;
  - against a lying challenger, the executor service's opening stood and the
    run was ruled E;
  - everything closed (64 s).
- **Offline:** the watchtower's claims are byte-identical to the offline
  first-divergence game. That covers 347 chunked disputes and 5 list lies
  (`python/tests/test_services_challenger.py`).

**Not yet measured:**
- a run on the testnet alpha program;
- sustained operation over many runs;
- priority fees and multi-node sends, which are C2's sequencer work.
