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
- **Bend settlement pilot: deferred (owner 2026-10-07).** Its uncommitted work
  from the main checkout is preserved unchanged on `wip/bend-settlement-pilot`
  (c6816ab, off 272ccf7, which still has revision 8); it is not wired into the
  program. Work in a worktree.

## Overnight loop 2026-10-06/07 (revision-8 retirement, branch `retire-rev8`)

Progress lines, newest last:

- 10-07 ~01:00: G1 inventory in `docs/plans/retire-revision-8.md` (96f8341).
  G2 removal committed (3d0d3e9 code, 87858db docs): default offline suite and
  doc tests pass. **Merge into main held:** the Bend settlement pilot's
  uncommitted work in the main checkout builds on revision 8 (options a/b/c in
  the plan). G3 feature-suite comparison against 272ccf7 running.
- 10-07 ~02:00: G3 done (plan "Verification"): v2.1/LX1/sessions/lanes/graph v2
  match 272ccf7; alpha image `7acbce49…` (routing test passes); Doom on DCG
  builds without `revision-8` and both its ProgramTests pass. G4 review: no
  critical/high; fixes in 57b6b4e. **Merge into DCG main not done:** waiting on
  the owner's Bend-pilot choice (a/b/c in the plan); the main checkout also has
  that session's uncommitted edits to `lib.rs` and `Cargo.toml`. S2 plan on
  Basanos branch `plan/dcg-doom-split` (14651e575). S1 (`9CHa…` closes) not
  started: needs the owner to say whether the program account itself closes.
- 10-07 morning (owner): Bend pilot deferred; its work committed as-is to
  `wip/bend-settlement-pilot` (c6816ab); main fast-forwarded to `retire-rev8`
  (revision 8 retired on main); Bend docs marked deferred. Not pushed.
