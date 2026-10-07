# Retiring the revision-8 lifecycle from DCG: plan (2026-10-06)

**Status: in progress on branch `retire-rev8` (2026-10-06 overnight); merge held, see "Blocker".** Agreed order with the owner (2026-10-06):
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

## Detailed inventory (2026-10-06, branch `retire-rev8` off 272ccf7)

Measured with grep over the tree at 272ccf7.

- **Revision-8-only program modules** (`crates/dcg-program/src`, about 41,000
  lines): `closure_v2{,_accounts,_generic,_proof,_response,_tree}`,
  `compatibility`, `desc_upload`, `descriptor`, `envelope_seal`,
  `position_template`, `pt1_onchain`, `pt2p`, `pt2p_onchain`,
  `region_commitment` (used only by `closure_v2_generic`), `root_only`,
  `root_only_challenge`, `root_only_sealed`, `seal`, and `unified/`
  (14 files).
- **Dispatch:** `lib.rs` tags 115–118, 120–129, 131, 132, 140–146, 156–169,
  172–178, 183–187, 193, 197–200, and `process_instruction`'s early 120–129
  route; `app_api::CORE_INSTRUCTION_TAGS_REVISION_8`.
- **Where the kept code touches revision 8** (the only places that are not
  plain deletion):
  - `kernel.rs`: `ApplicationManifest`'s `legacy_forms`,
    `require_legacy_form_binding`, `admission_scan`, `hooks`,
    `decision_routes`; `LegacyFormBinding`, `ClosedRegistryAdapter`, the
    legacy-form replay helpers, `admission_identity_digest`,
    `ruling_identity`, `replay_leaf_digest` (uses `closure_v2::hash`); the
    test manifests.
  - `app_api.rs`: the dispute hooks over `unified::challenge` and the
    revision-8 account seeds; the core tag table.
  - `kernel_svm.rs`: `unified::DCR1_AUTH`/`DCR1_BAD` error codes.
  - `kernels/mod.rs`: `descriptor::err::EXEC_KERNEL_GEOMETRY`.
  - `commit/fold.rs`: `descriptor::DcgError`.
  - `disputes_v21_lx.rs` tests: `REVISION8_COMPATIBILITY` in test manifests.
  - v2.1 (`disputes_v21*`), sessions (`stateful*`), `graph_v2`,
    `kernel_kit`, `account_provenance`, `hash` do not use revision-8 code.
- **Features:** `revision-7`, `revision-8`, `revision-8-lifecycle`,
  `test-rev8-before-payer-alias-fix`, `test-weakened-class-rule`,
  `test-legacy-unchecked-option-range`, `sbf-unbound-form-test`,
  `sbf-attested-admission-test` (both only exercise revision-8 admission).
- **Tests that go with it:** `unified_v8_{bond,document,records,resolve_check}`,
  `legacy_dcr1_forgery`, `lifecycle_property_harness`, `referee_laws`
  (revision-8 mechanics; v2.1's laws live in `disputes_v21_*`),
  `position_template_extraction_regressions`, `region_commitment`,
  `test_support_{challenge,decision,document,template}`; the revision-8 rows
  of `portable_goldens` and `account_provenance_lint`'s allowlist.
- **Crate:** `dcg-test-support` is entirely the revision-8 real-flow state
  builder (template, document, challenge, decision stages); no surviving test
  uses it.
- **Fixtures and goldens:** `crates/dcg-program/tests/fixtures/closure_v2_generic`,
  `tests/golden/dcg/{unified_v8,unified_v1_executor_rung_d_80.json,unified_v7.json,
  closure_v2_real_rev7.json,root_only_real_rev7.json,range_summary_rs1_rungd_80.json,
  rev8_census_registry_rows_v*.tsv,pt2_variable,form47_pxr1_routes_v1.bin,
  pxr1_form47_k35_compiler_v1.bin,lifecycle/region_content_v1.tsv}` (each
  checked for other users before removal).
- **Scripts and examples:** `scripts/run-rev8-sbf-suites.sh`;
  `examples/hello-dispute` (runs the revision-8 SBF suite over Basanos PT2P
  files); `examples/session-app` builds with `revision-8` (feature only).
- **Docs:** `docs/revision-8-extraction.md`, `docs/revision-8-handlers.md`,
  `docs/spec/referee-laws.md` (revision 8; v2.1 has its own),
  `docs/spec/app-bound-replay-v1.md`, `docs/design/test-support-v1.md`,
  `docs/design/tag124-replay-interface-v2.md`; mentions in README, AGENTS,
  getting-started, application-api and others.
- **Python client:** no revision-8 code (one comment in
  `python/tests/test_local_validator.py`).
- **Consumers' manifests:** Doom (`DOOM_DCG_APPLICATION_MANIFEST`), Basanos
  (`mainnet_v21::MANIFEST`, `v21_test_image::MANIFEST`) and
  `examples/kernel-app` name `hooks`/`decision_routes:
  &REVISION8_COMPATIBILITY`, with empty legacy forms.

## Interface choice for this release

Per step 2, the manifest keeps its old field shape for one release, marked
deprecated, so Doom and Basanos compile unchanged when they next pin a tag:
`legacy_forms`, `require_legacy_form_binding`, `admission_scan`, `hooks` and
`decision_routes` stay as fields but no route reads them, and `validate()`
refuses a manifest that sets legacy forms or requires them.
`compatibility` shrinks to the two marker traits and the inert
`REVISION8_COMPATIBILITY` value. Tags 115–200 are refused by DCG's
dispatcher; every tag revision 8 routed (and 120–129) stays in the core tag
set, so an application cannot reuse a revision-8 tag number. The next release
removes the deprecated fields.

**Consumer migration note.** Basanos's `chain/dcg-program` selects
`dcg_core/revision-8` through its `revision-8-code` feature (the mainnet
image included) and has its own revision-8 code over DCG's modules. Its pin
stays on v0.1.0-alpha; when it next moves to a DCG release without revision 8,
Basanos removes its revision-8 code and `revision-8-code` first, then
rebuilds and requalifies the image (owner's go for any mainnet upgrade).

**Follow-up for Basanos (review 10-07, M2).** DCG's provenance lint used to
read Basanos's `chain/dcg-program/Cargo.toml` and refuse `graph-v2-raw-write`
in the switchover feature set. That cross-repo check is gone from DCG; port it
into Basanos's own `chain/dcg-program` tests when Basanos next touches its DCG
pin.

## Blocker found 2026-10-06: the Bend settlement pilot builds on revision 8

Another session's uncommitted work in the main DCG checkout (features
`bend-settlement-pilot`, `bend-*-executor`, modules `settlement_identity*`,
the `bend/` directory) links the revision-8 lifecycle: `unified` (document,
address, result, registry, config, classes), `closure_v2_response`,
`pt2p_onchain`, `root_only_sealed`, `compatibility`, and enables
`revision-8`. Deleting revision 8 on main breaks that work. The branch work
here is independent of it; **merging into main waits for an owner decision**:

- (a) the pilot builds against the v0.1.0-alpha tag (which keeps revision 8);
- (b) revision 8 stays on main until the pilot ends, and this branch waits;
- (c) revision 8 moves into a separate crate the pilot depends on.

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
