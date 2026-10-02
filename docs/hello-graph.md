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

After the 10-02 conformance upgrades, all five pass again with verified admission and a 1,000,000-lamport executor bond (`DCG_BOND=1000000`).

**Root-committed descent** (`examples/hello-graph/hello_descent.py`, 10-02):

| case | path | ruling | wall |
|---|---|---|---|
| dishonest-add | root → child region 1 → leaf 0, external inputs | challenger | 9.3 s |
| dishonest-identity | root leaf 0, input authenticated by child region root | challenger | 7.1 s |
| forged-input | root leaf 0, input contradicts child output | challenger (authentication) | 7.0 s |
| honest | root → child → leaf 0 | executor; final after window | 13.9 s |
| honest-root-leaf | root leaf 0 | executor; final after window | 14.1 s |
| silent | executor never reveals | challenger at deadline | 15.3 s |

**Kernel parity:** `scripts/kernel_parity.py` runs `crates/dcg-kernels/tests/vectors/parity-v1.json` through tag 215. All 8 cases match the host, including both overflow refusals.

## On-chain surface

The instructions live in `crates/dcg-program/src/graph_v2.rs` and use tags 208–226:
- 208: raw write;
- 209: close run;
- 210–212: blob create, write and seal;
- 213: admit template;
- 214: init run;
- 215: execute;
- 216: commit;
- 217: challenge;
- 218: finalize;
- 219: sampling audit;
- 220: commit a root region digest (root-committed runs);
- 221: open a dispute;
- 222: reveal a region (`RegionRootV1`);
- 223: choose a child region or a leaf;
- 224: reveal a leaf and its Merkle path;
- 225: replay a leaf with authenticated inputs;
- 226: settle at a deadline, or finalize an idle run.

Canonical DCGG/DCPL blobs are decoded at admission by `crates/dcg-wire`, a `no_std` port of the reference refusal rules checked against the golden corpus. A wire refusal is `0x6400 + code`.

Kernels come from `crates/dcg-kernels`, which is `no_std`. The same source is used on the host and in SBF.

## Shortcuts against the v2.0 spec

- **DCPL is decoded on chain for canonical blobs.** Admission verifies that the executed table equals the plan's lowering. The tracer emits canonical DCGG/DCPL for every shape the format can express. Only inexpressible shapes (an external input used twice or never, a dead step, an output that is a raw input) fall back to `DCGGF1` with a trusted table (template byte 6 = 0). The template's mode is bound to the plan: every graph and plan region must resolve in the template's mode (sampling counts as optimistic), or admission refuses with `0x621f`. The golden Hello pair is the optimistic one; consensus Hello uses its own canonical consensus-mode pair.
- **Fixed 4-byte cells** and at most 8 inputs per step.
- **Two dispute paths.** Trace-committed runs (216/217) keep direct one-step replay. Root-committed runs (220–226) descend root → region → step. The **value digest is provisional**: `SHA256("dcg.value.v2.provisional\0" || bytes)`, because the frozen spec leaves it open. Inputs are authenticated when they come from an external input, a same-region producer, a child-region producer, or a producer in the parent region the descent came from (`parent_child_descent.py`). Producers two or more regions up are not authenticated yet.
- **Bonds.** The executor posts the template's bond at commit; it goes to a winning challenger or auditor and is refunded at finalize. In root-committed descent the challenger posts the same bond when it opens a dispute (221): a losing challenger's bond goes to the executor, and a winning challenger gets it back. There is no protocol fee.
- **Image identity** is a hash of the program ID, not of the ELF.
- **Encodings.** The tracer emits the golden DCGG/DCPL bytes only for the exact two-level add/identity shape. Other shapes get a fast `DCGGF1`/`DCPLF1` encoding.
