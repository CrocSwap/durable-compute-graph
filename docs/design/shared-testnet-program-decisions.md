# Shared DCG v2 testnet program: owner decisions

**Status: decision brief; recommendations are designed policy, not an existing
owner choice or deployment plan.** The v2.0 shared testnet program has no
program ID or deployed image yet. These decisions must be recorded before the
first template is admitted. A testnet deployment is a later, separately
reviewable action.

| Owner decision | What must be chosen | Recommendation | Reason and guard |
|---|---|---|---|
| Upgrade authority | Which person or authority can change the shared executable or its registry? | Use an owner-controlled 2-of-3 multisig held by the project owner plus two independent recovery signers. Keep worker and application keys out of the authority set. | No single operator can silently replace dispute semantics. Publish the authority address and recovery process with each release. |
| Starter kernel set | Which callbacks are linked into the first general image? | Start with only `add_i32/1` and `identity_i32/1`, each stateless and checked, using the frozen capability IDs and test vectors. | This is the smallest useful vertical slice. Add kernels only after host/SBF byte and refusal parity passes on the actual handler. |
| Upgrade and versioning policy | In-place upgrade, new program address, or immutable releases; what changes require a new version? | Keep each admitted executable image immutable while any template or dispute refers to it. Put an incompatible release at a new program address; permit an in-place testnet upgrade only before templates are admitted or after every dependent run/dispute is terminal. Bind `program_id`, image identity, `DCKC` root, `DCGG/DCPL` profile, and compiler identity in the admission receipt. | A challenge must replay against the code identity the plan committed to. Record the image hash for every release. Any field/meaning/refusal change follows the three-package change-control rule. |
| Fees and rent | Who funds deployment, template shards, run/dispute accounts, and transaction fees; what may be reclaimed? | Project treasury pays the shared executable and shared registry rent. The application pays its graph/plan shard rent, run/dispute account rent, and transaction fees. Publish the rent estimate before admission; return reclaimable account rent only after terminal finality and retain receipt details. Do not add a protocol service fee in the first testnet slice. | Separates one-time shared infrastructure from app-specific workload cost. Actual rent and fees must be recorded per run; estimates are not measurements. |
| Abuse limits | What per-image, per-application, and per-authority caps apply? | Enforce the frozen v2.0 limits at admission (4 MiB graph/plan, 16,384 steps, depth 8, openings 4 KiB), then apply lower measured per-image CU/account/heap/stack limits. Bound live templates, runs, disputes, total rent, and submit rate per authority; require the versioned app settlement/bond policy before optimistic admission. | The format ceilings are designed, not chain capacity. Start with a small testnet quota and raise it only from receipts that record actual CU, fees, rent, unresolved fates, and refusal behavior. |

## Release checklist

Before the first template, the owner should publish one release record containing
all five decisions, the program address, upgrade authority, executable image
SHA-256, DCKC manifest root, starter-kernel list, supported graph/plan profile,
configured CU/account limits, rent payer policy, per-authority quotas, and the
receipt location. The admission path must compare the template's exact image
and capability identities with that release record.

The testnet program is a shared deployment target, not an extension of the
frozen graph bytes. Custom kernels still require an app-specific static image.
No deployment or chain transaction is part of this document.
