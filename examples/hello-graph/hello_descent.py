"""Hello Graph root-committed run and dispute descent on a live cluster.

Usage: hello_descent.py {dishonest-add|dishonest-identity|forged-input|honest|honest-root-leaf|silent}
Environment: DCG_PAYER_KEYPAIR, DCG_PROGRAM_ID, DCG_RPC_URL.
"""
import sys, importlib.util, json, time
from dcg.graph_client import GraphClient
from dcg import tracing, descent
case = sys.argv[1] if len(sys.argv) > 1 else "dishonest-add"
sys.argv=['x']
spec=importlib.util.spec_from_file_location('h','examples/hello-graph/hello_graph.py'); h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
c=GraphClient.from_environment(); g=tracing.trace(h.hello); D=descent.DescentClient(c)
a=c.admit(g,"optimistic",window_slots=300,samples=2,bond=1_000_000)
run=c.init_run(a,[20,22]); run_id=c.account(run)[32:64]
trace={"forged-input":[42,43],"dishonest-add":[43,43],"dishonest-identity":[42,43],"honest":[42,42],"honest-root-leaf":[42,42],"silent":[43,43]}[case]
import struct
com=descent.build(g, run_id, [20,22], trace, forge={(2,0,0): struct.pack("<i",43)} if case=="forged-input" else None)
t0=time.monotonic()
def log(m): print(json.dumps({"case":case,"step":m,**D.read(run),"run":c.read_run(run)["status"],"t":round(time.monotonic()-t0,1)}), flush=True)
D.commit_root(a,run,com,trace,c.payer); log("commit_root")
D.open(a,run,c.payer); log("open")
if case=="silent":
    st=c.read_run(run); dd=D.read(run); c.wait_past(dd["deadline"]); D.settle(a,run,c.payer.pubkey(),c.payer.pubkey()); log("settle-after-silence"); sys.exit()
D.reveal_region(a,run,com,0,c.payer); log("reveal root")
if case in ("dishonest-identity","honest-root-leaf","forged-input"):
    D.choose(a,run,1,0,c.payer); log("choose root leaf 0")
    D.reveal_leaf(a,run,com,0,0,c.payer); log("reveal leaf")
    D.replay(a,run,g,com,0,0,c.payer); log("replay (input authenticated via child region)")
else:
    D.choose(a,run,0,1,c.payer); log("choose child 1")
    D.reveal_region(a,run,com,1,c.payer); log("reveal child")
    D.choose(a,run,1,0,c.payer); log("choose leaf 0")
    D.reveal_leaf(a,run,com,1,0,c.payer); log("reveal leaf")
    D.replay(a,run,g,com,1,0,c.payer); log("replay (external inputs)")
if case.startswith("honest"):
    st=c.read_run(run); c.wait_past(st["deadline"]); D.settle(a,run,c.payer.pubkey(),c.payer.pubkey()); log("settle after window")
