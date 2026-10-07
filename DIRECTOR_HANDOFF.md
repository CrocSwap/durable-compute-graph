# DCG director handoff

Ephemeral state for whoever directs DCG next. Standing rules are in
`docs/project-rules.md`; this file is only what is in flight.

## State (2026-10-06)

- **Released:** v0.1.0-alpha. All alpha exit criteria are met; see
  `docs/plans/alpha-release-plan.md`.
- **Shared testnet program `J9Eje…`:** runs image `8d39d440…`, which predates
  version-1 runs (sub 28).
- **Consumers:**
  - **Basanos.** Its mainnet program `2HxnyJvw…` (2026-10-06) is built
    from DCG `7d1aac5` with Basanos's own LX1 machine. Its testnet switchover
    program `9CHa…` still uses the revision-8 lifecycle.
  - **Doom on DCG.** Testnet program `2uHBWbYE…`, a stateful v3 session with
    lanes.
- **Next, in order:**
  1. consumers pin tags;
  2. retire revision 8, after an owner decision on `9CHa…`;
  3. Doom to its own repo.

  See `docs/plans/post-alpha-roadmap.md`.
- **Owner answers (10-06):**
  - the release terms now say mainnet at your own risk;
  - `9CHa…` is retired, so revision 8 is deleted from DCG rather than moved.
- **Shared checkout:** another session works in the main DCG checkout
  (settlement and bend identity, uncommitted). Work in a worktree.

## Overnight loop 2026-10-06/07 (revision-8 retirement, branch `retire-rev8`)

Progress lines, newest last:

- 10-07 ~01:00: G1 inventory in `docs/plans/retire-revision-8.md` (96f8341).
  G2 removal committed (3d0d3e9 code, 87858db docs): default offline suite and
  doc tests pass. **Merge into main held:** the Bend settlement pilot's
  uncommitted work in the main checkout builds on revision 8 (options a/b/c in
  the plan). G3 feature-suite comparison against 272ccf7 running.
