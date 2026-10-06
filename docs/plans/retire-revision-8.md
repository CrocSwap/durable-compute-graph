# Retiring the revision-8 lifecycle from DCG: plan (2026-10-06)

**Status: designed; not started.** Agreed order with the owner (2026-10-06):
tag the first release, switch consumers to tags, then this.

## Why

DCG began as an extraction of Basanos's revision-8 document lifecycle. That
code (tags 115–200, the closure, unified, PT1/PT2 seal and descriptor modules,
about 26,000 lines in `crates/dcg-program/src`) is Basanos-specific, and 90
files in DCG still mention Basanos. Basanos now runs on v2.1 on mainnet
(2026-10-06), and revision 8 never went to mainnet, so DCG no longer needs to
carry it.

## Inventory

- **Modules (revision-8 only):**
  - `descriptor`, `desc_upload`, `position_template`;
  - `closure_v2` and `closure_v2_{accounts,generic,proof,response,tree}`;
  - `pt1_onchain`, `pt2p`, `pt2p_onchain`;
  - `seal`, `envelope_seal`;
  - `root_only`, `root_only_sealed`, `root_only_challenge`;
  - `unified/`;
  - `compatibility` (the `REVISION8_COMPATIBILITY` adapter and the Basanos
    registry table).
- **Features:** `revision-7`, `revision-8` (the base gate), `revision-8-lifecycle`,
  `test-rev8-before-payer-alias-fix`, `test-weakened-class-rule`,
  `test-legacy-unchecked-option-range`.
- **Tests and support:**
  - the revision-8 integration tests;
  - the Basanos PT2P fixtures in `dcg-test-support` (`BASANOS_ROOT`);
  - `scripts/run-rev8-sbf-suites.sh`;
  - `docs/revision-8-*.md`.
- **The coupling that is not just deletion.** The application interface
  carries revision-8 hooks:
  - `kernel::ApplicationManifest`'s `hooks`, `decision_routes`,
    `legacy_forms` and `require_legacy_form_binding`;
  - `app_api::ApplicationProgramManifest`'s dispute hooks over `unified`.

  Every application names `hooks: &REVISION8_COMPATIBILITY` today (Basanos's
  mainnet image, Doom, the examples).

## Steps

1. **Owner decision (10-06): retire `9CHa…`.** Revision 8 is deleted (it
   stays in git history and in v0.1.0-alpha); Basanos closes `9CHa…`'s
   accounts for rent. The alternatives considered were:
   - If yes: revision 8 moves to a Basanos-owned crate (built against the last
     DCG tag that has it).
   - If no: it is deleted; it stays in git history and in that tag.
2. **The application interface (breaking).** A manifest without revision-8
   hooks: kernels, modes, admission scan. Keep the old shape for one release,
   marked deprecated, with the migration in `CHANGELOG.md`. Basanos (the
   mainnet image wrapper) and Doom migrate when they next pin a tag.
3. **Remove** the lifecycle dispatch (tags 115–200 and 120–129), the modules,
   the features and their tests, and the Basanos fixtures and `BASANOS_ROOT`
   hooks.
4. **Images.**
   - The alpha image's bytes will change: rebuild twice and requalify, and
     upgrade the shared program `J9Eje…` only with the owner's OK.
   - Basanos's mainnet program is unaffected until its next upgrade, which
     needs the owner's go.
5. **Independent review** of the interface change, then merge and tag.

**Estimate:** 2 to 4 days, plus the review. **Not affected:** v2.1 disputes,
LX1, sessions and lanes, the sequencer and the Python client.
