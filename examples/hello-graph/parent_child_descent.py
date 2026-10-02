"""A parent -> child -> parent graph: canonical v2.0 lowering, verified admission and
descent into the child region, whose input is produced in the parent region.

Usage: parent_child_descent.py {consensus|dishonest-child|forged-child-input|honest-child}
Environment: DCG_PAYER_KEYPAIR, DCG_PROGRAM_ID, DCG_RPC_URL.
"""
import sys, json, time, struct
from dcg.graph_client import GraphClient
from dcg import tracing, descent
from dcg.kernels import add_i32, identity_i32
case = sys.argv[1]
def pc(a, b):
    s = add_i32(a, b)
    with tracing.region("child"):
        t = identity_i32(s)
    return identity_i32(t)
c=GraphClient.from_environment(); g=tracing.trace(pc); D=descent.DescentClient(c)
t0=time.monotonic()
if case=="consensus":
    a=c.admit(g,"consensus",window_slots=300,samples=2)
    run=c.init_run(a,[20,22]); c.execute(a,run)
    print(json.dumps({"case":case,"verified":c.account(a["template"])[6],"run":c.read_run(run)})); sys.exit()
a=c.admit(g,"optimistic",window_slots=300,samples=2,bond=1_000_000)
print(json.dumps({"case":case,"template_verified":c.account(a["template"])[6]}))
run=c.init_run(a,[20,22]); run_id=c.account(run)[32:64]
trace={"dishonest-child":[42,43,43],"forged-child-input":[42,43,43],"honest-child":[42,42,42]}[case]
forge={(2,0,0):struct.pack("<i",43)} if case=="forged-child-input" else None
com=descent.build(g, run_id, [20,22], trace, forge=forge)
def log(m): print(json.dumps({"case":case,"step":m,**D.read(run),"run":c.read_run(run)["status"],"t":round(time.monotonic()-t0,1)}), flush=True)
D.commit_root(a,run,com,trace,c.payer); D.open(a,run,c.payer); D.reveal_region(a,run,com,0,c.payer)
D.choose(a,run,0,1,c.payer); D.reveal_region(a,run,com,1,c.payer); D.choose(a,run,1,0,c.payer)
D.reveal_leaf(a,run,com,1,0,c.payer); log("leaf revealed")
D.replay(a,run,g,com,1,0,c.payer); log("replay (input from parent region, auth kind 3)")
