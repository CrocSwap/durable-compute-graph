# Project rules

A living list: if a rule seems wrong or costly, say so (the director raises it
with the owner; a dispatched agent says so in its report), and keep following
it while it is discussed unless that would clearly cause harm. Kept to about
ten rules; a rule born of one incident starts in that task's brief.

1. **Mainnet needs the owner's explicit go**, per action, with a spend cap.
   Testnet is fine. The release terms (`docs/release-terms.md`) speak to
   outside users.
2. **The shared testnet alpha program** (`J9Eje…`) is upgraded only with the
   owner's OK; record each image's sha256 and two-build receipt in
   `docs/hello-graph.md`. Development programs may be upgraded freely. Never
   print keys; keys are owner-only files (0600) in 0700 directories.
3. **No on-chain step over 90 seconds** unless the owner agreed a variance.
   Run chain steps under a stage cap; a slow chain step is a design smell.
   Builds and offline work have no limit.
4. **Senders fire and forget**, then one readback pass resends what is
   missing; confirm only where the next step needs the result.
5. **Rebuild only when program source changed.** Published images (the
   shared program, a consumer's mainnet image) need two equal reproducible
   builds.
6. **No hand-built state.** Tests reach mid-protocol state through real
   instructions or reference-generated scenarios; a state
   the current program forbids comes from a named test-only legacy mode. A
   test lives with the code that owns the behavior.
7. **Endings and payouts are tested adversarially and reviewed
   independently.** Every stated invariant is tested over every ending; each
   permissionless instruction's design says who profits by calling it first;
   a change to payouts, bonds or endings gets an independent review before it
   merges to main.
8. **Label numbers** measured / estimated / designed / open, and keep failed
   results; a measured claim names its experiment note.
9. **Preserve uncommitted changes** in shared checkouts; work in a worktree.
10. **Never touch the external archive disk (`/Volumes/HddCrypto3`).**
