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
print(graph.explain("optimistic")) # regions and modes, imports, kernels, guarantee, ceilings;
                                   # raises TraceError instead of stating a guarantee the program lacks
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

The instructions live in `crates/dcg-program/src/graph_v2.rs` and use tags 208–226. Three features route them (split after the 2026-10-02 review):
- `graph-v2`: the trace-committed path, 209–218. Records are accepted only at their derived addresses, a pre-funded address can still be created, the challenge window is 1 to 10,000,000 slots, and a payer can close a run nobody committed. Native program tests: `cargo test -p dcg-program --features graph-v2 --test graph_v2_trace`.
- `graph-v2-experimental`: adds the sampling audit (219) and root-committed descent (220–226), both under redesign. Without it, a sampling template is refused at admission.
- `graph-v2-raw-write`: tag 208, for testnet resource uploads only.

**The alpha shared image is `--features alpha-image`** (owner 2026-10-05, R2 review B-M2): tag 227 (v2.1 disputes with LX1) and the example kernels (`dcg-alpha/1`: byte-sum, SHA-256 concat, the toy LX1 machine), with no test, v2.0 (208–226) or revision-8 lifecycle routes; build it with `scripts/build-alpha-image.sh OUT` (two builds, byte-equal, receipt with the sha256). The v2.0 Hello Graph below needs the older test-feature image (`--features "sbf-lifecycle-test sbf-real-lifecycle-test graph-v2-experimental graph-v21"`); it is not part of the alpha. The image currently deployed was built with `--features "sbf-lifecycle-test sbf-real-lifecycle-test graph-v2-experimental graph-v2-raw-write graph-v21"`. It was last upgraded on 2026-10-02 from 5744f52 (committed constants): image sha256 `7b04f8d5…d231`, 1,766,136 bytes, verified by dump; Hello Graph passes on it. Measured on testnet: chunked-kernel replay 23/23 (38fb13e), real Basanos form-22 captures 6/6 (4229294, via `dcg-test-sha-v1` and 64 KiB staged witnesses), and committed-constant scenarios 26/26 including two refused forged ConstSpec openings (5744f52). Logs in Basanos `out/runs/dcg-chunked-testnet-2026-10-02/` and `out/runs/dcg-v21-form22-2026-10-02/`. Tags in that deployed image:
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
- **Two dispute paths.** Trace-committed runs (216/217) keep direct one-step replay. Root-committed runs (220–226) descend root → region → step. The value digest is `SHA256("dcg.value.v2\0" || bytes)` (spec §5, decided 2026-10-02). Inputs are authenticated when they come from an external input, a same-region producer, a child-region producer, or a producer in the parent region the descent came from (`parent_child_descent.py`). Producers in a sibling region, or two or more regions away, are not authenticated yet. The 2026-10-02 review found the descent unsound in its current form (B2–B5, B7 in Basanos `out/runs/review-dcg-graph-v2-2026-10-02.md`), so `explain()` refuses root commitments and sampling until the redesign.
- **Bonds.** The executor posts the template's bond at commit; it goes to a winning challenger or auditor and is refunded at finalize. In root-committed descent the challenger posts the same bond when it opens a dispute (221): a losing challenger's bond goes to the executor, and a winning challenger gets it back. There is no protocol fee.
- **Image identity** is a hash of the program ID, not of the ELF.
- **Encodings.** The tracer emits the golden DCGG/DCPL bytes only for the exact two-level add/identity shape. Other shapes get a fast `DCGGF1`/`DCPLF1` encoding.
