"""Hello Graph on a live cluster: trace, explain, admit, run, dispute, audit.

Usage: hello_graph.py {consensus|optimistic|dishonest|sampling|sampling-dishonest|all}
Environment: DCG_PAYER_KEYPAIR, DCG_PROGRAM_ID, DCG_RPC_URL.
"""

from __future__ import annotations

import sys
import time

from dcg import tracing
from dcg.graph_client import GraphClient
from dcg.kernels import add_i32, identity_i32


def hello(a, b):
    with tracing.region("child"):
        total = add_i32(a, b)
    return identity_i32(total)


def main(scenario: str) -> int:
    graph = tracing.trace(hello)
    client = GraphClient.from_environment()
    inputs = [20, 22]
    honest = graph.evaluate(*inputs)
    scenarios = ["consensus", "optimistic", "dishonest", "sampling", "sampling-dishonest"] if scenario == "all" else [scenario]
    for name in scenarios:
        started = time.monotonic()
        mode = "sampling" if name.startswith("sampling") else ("consensus" if name == "consensus" else "optimistic")
        print(f"== {name}")
        print(graph.explain(mode, samples=2))
        admitted = client.admit(graph, mode, window_slots=150, samples=2)
        run = client.init_run(admitted, inputs)
        if mode == "consensus":
            client.execute(admitted, run)
        else:
            trace = list(honest)
            if name.endswith("dishonest"):
                trace = [trace[0] + 1, trace[1] + 1]  # wrong add, consistent identity
            client.commit(admitted, run, trace)
            state = client.read_run(run)
            if name == "dishonest":
                client.challenge(admitted, run, 0)
            elif mode == "sampling":
                client.wait_past(state["commit_slot"])
                client.audit(admitted, run)
            if client.read_run(run)["status"] == "committed":
                try:
                    client.challenge(admitted, run, 0)
                    print("  unexpected: honest step challenge accepted")
                except Exception as exc:
                    print(f"  matching opening refused as expected: {str(exc)[:80]}")
                client.wait_past(state["deadline"])
                client.finalize(admitted, run)
        state = client.read_run(run)
        outputs = graph.outputs_of(state["trace"])
        print(f"  run {run} status={state['status']} trace={state['trace']} outputs={outputs} "
              f"bad_step={state['bad_step']} audited={state['audited']} wall={time.monotonic() - started:.1f}s")
        client.close(admitted, run)
    print(f"transactions: {len(client.signatures)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "all"))
