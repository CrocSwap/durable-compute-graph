# Hello Graph (DCG v2 fast path)

**Status: fast-path implementation, measured on Fogo testnet 2026-10-01.** It
is a mechanics demonstration. It takes shortcuts against the frozen v2.0 spec,
listed at the end.

## What it does

```python
from dcg import tracing
from dcg.kernels import add_i32, identity_i32

def hello(a, b):
    with tracing.region("child"):
        total = add_i32(a, b)
    return identity_i32(total)

graph = tracing.trace(hello)      # static trace; refuses data-dependent control flow
print(graph.explain("optimistic")) # kernels, regions, source lines, guarantee, ceilings
graph.evaluate(20, 22)             # host execution: [42, 42]
```

`dcg.graph_client.GraphClient` admits the graph and runs it on chain:
- `admit(graph, mode)` uploads the graph, plan and step-table blobs once each, sealed against their hashes. It then creates the template.
- `init_run(admitted, inputs)` creates a run.
- Consensus mode calls `execute`: every step runs on chain.
- Optimistic and sampling modes call `commit` with the full trace. Then:
  - `challenge(step)` replays one step on chain before the deadline;
  - `audit` (sampling mode) replays steps chosen by a slot hash newer than the commit;
  - `finalize` runs after the deadline.
- `close` returns the run's rent.

```sh
export DCG_PAYER_KEYPAIR=... DCG_PROGRAM_ID=... DCG_RPC_URL=https://testnet.fogo.io
PYTHONPATH=python python/.venv/bin/python examples/hello-graph/hello_graph.py all
```

## Measured on Fogo testnet (program FCzAE7H9…BZox)

| scenario | result | wall |
|---|---|---|
| consensus | final, output 42 | 10.8 s (includes first blob upload) |
| optimistic honest | matching-step challenge refused; final after deadline | 9.3 s |
| dishonest executor (43) | challenge on step 0 → challenger_won | 6.8 s |
| sampling honest | audited, final | 13.0 s |
| sampling dishonest | audit caught step 0 → challenger_won | 3.7 s |

## On-chain surface

The instructions live in `crates/dcg-program/src/graph_v2.rs` and use tags 208–219:
- 208: raw write;
- 209: close run;
- 210–212: blob create, write and seal;
- 213: admit template;
- 214: init run;
- 215: execute;
- 216: commit;
- 217: challenge;
- 218: finalize;
- 219: sampling audit.

Kernels come from `crates/dcg-kernels`, which is `no_std`. The same source is used on the host and in SBF.

## Shortcuts against the v2.0 spec

- **No DCPL decoding on chain.** The program trusts the template admitter's lowered step table. The graph and plan blobs are bound by hash only.
- **Fixed 4-byte cells** and at most 8 inputs per step.
- **Direct step replay.** A challenge replays one step directly over the on-chain trace, instead of descending root → region → step.
- **No bonds, fees or slashing.** A ruling only sets the run status.
- **Image identity** is a hash of the program ID, not of the ELF.
- **Encodings.** The tracer emits the golden DCGG/DCPL bytes only for the exact two-level add/identity shape. Other shapes get a fast `DCGGF1`/`DCPLF1` encoding.
