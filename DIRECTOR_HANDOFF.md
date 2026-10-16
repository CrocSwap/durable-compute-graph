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
- 10-09 unattended loop: branch `hygiene-chunked-oracle-gate` (ff3a2fe, local, not merged): `disputes_v21_chunked_oracle` gated on `graph-v21` + `example-kernels` (plain graph-v21: 0 tests; both: 2 passed, 24 s); roadmap hygiene items marked done. Owner: merge and push when convenient.
- 10-13 (owner: fix the publicity gaps 1 and 6): the shared testnet program `J9Eje…` upgraded in place to the v0.2.0-alpha image `7acbce49…` (344,304 bytes, two builds equal at the tag); finalized readback byte-equal, only tag 227 routes, sub 28 routes, `dcg verify` ok, both hello-graph dispute examples rule as the oracle and settle (receipts: Basanos `out/runs/dcg-alpha-v020-2026-10-13/`). README opening grammar fixed; GitHub Releases created for v0.1.0-alpha and v0.2.0-alpha from the CHANGELOG.
- 10-14 (owner): release terms reviewed and accepted (runtime-version claim corrected: crates' version, not bumped per tag; sha256 identifies the image); post-alpha roadmap accepted; license stays GPL-3.0-only.
- 10-14 (owner: v0.3.0 items 1, 2, 4 + fuel, verdict reader, frames; item 3 deferred, hook takes a list; item 5 design LX2): branch `v030-session-capabilities` (local, not pushed), through 7ec8ab8. Two independent reviews (no critical; one high in the test-only conformance entry, fixed). Native and SBF suites, kit compare (1,928 cases identical) and fuzz campaigns clean (last: seed 1020 x1000, 88,516 txs, 153 resource and 65 tick sessions). Alpha image bytes change (d111417f at 6c10ccc), so the release needs a shared-program upgrade with a week's notice. Next: owner's go to push a preview for qushta; crate version bump to 0.3.0 at release.
- 10-14 (later): branch pushed to origin at 66d14ea (owner's go). Then locally: version 0.3.0 (b32643d; marker `dcg-runtime/1 0.3.0`), alpha image `1da74d34757164854f81fc3d8b06ade350b5cac3c5d23ab26e7bf8378fbc70d6` (344,304 bytes, two builds equal at b32643d); test fixes 081f1d6 (provenance allowlist gains the test-only `serve_account_request`; the runtime-marker test was stale since 3d0d3e9 and failed on main too). Checks: Python 361 passed; native `--all-targets` 75 passed; dcg-program with `sbf-real-lifecycle-test` on the SBF test image (`V3_SBF=1 V3_CONFORM_ENTRY=1`) 118 passed, 2 ignored (fuzz campaigns). Not rerun after the bump: kit compare, fuzz campaigns. Next: owner's go to push these commits; at release, tag, rebuild the image at the tag, a week's notice, then upgrade `J9Eje…`; merge to main needs the owner.
- 10-15 overnight queue (branch `result-records`, local only). Item 1: fuzz campaigns with seal ops are clean: native seed 1032 (1,000 sequences, 91,856 txs, 65 seals begun) and SBF seed 1033 (200 sequences, 18,195 txs, 21 seals begun); nothing to fix.
- Item 2: review test gaps closed. A test-only kernel `dcg-bigseal-v1` (two 40,000-byte spans) halts on a command; its 80,000-byte state seals through the program's chunk handler (the first chunk crosses the span boundary, the last is short), native and SBF, and opens against the host model's state. An LX1 run fixture (live and receipt) reads the same in Python; a refuted receipt is not a result (Rust real flow, Python).
- Item 3: reader and opening compute measured on SBF through a test-only probe (tag 251, `sbf-real-lifecycle-test` image only, writes nothing): session read about 5,260 CU; state opening 1,545 CU for 16 bytes and 41,898 CU for 80,000 bytes (about 33,000 per 64 KiB, estimated); run read 3,878 (generic) and 2,379 (LX1) CU, live or receipt; one-output opening 285 CU. In `docs/stateful-workloads-v3.md` and the design note.
- Item 4: `examples/composed-app` (kernel `dcg-importsum-v1`): raw writes refused; IMPORT reads a v2.1 run result, requires the trusted template and a 750-slot window, opens the output and checks its bytes, then writes them through the runtime's WRITE_INPUT. On the Hello run's real bytes (live and receipt) the session sums 42 + 42 = 84; refusals for raw write, wrong value, wrong path, committed, refuted, untrusted template, foreign owner. Native and SBF (image 394,440 bytes).
- Item 5: independent re-review of 294b74c..ac0720f: no critical or high; the first review's findings 1-4 are closed on both layouts; no way found to get an unverified input into composed-app. Addressed: a seal no longer checks the stream (closing it after the halt blocked the seal for good); `read_verdict` doc warns its resource fields zero after cleanup; fuzzer favours seals after a kernel halt (seed 1041: 47 seals begun in 300 sequences, clean); compute figure corrected to about 33,000 CU per 64 KiB; composed-app README states its trust limits (FINAL means unchallenged, anyone can make a run of the template, the authority picks what enters, the host is trusted); example tests for a short window and a swapped template. Checks after the fixes: SBF feature suite 130 passed, native result/fuzz smoke 14, plain 82, v2.1 73, Python 366 (5 skipped), example native and SBF. Left as documented: Python's session reader checks fewer record rules than Rust (both refuse every record the program would not write). Tooling note: building an example in the shared target dir right before the dcg-program feature suite broke that suite's build once (unresolved `stateful_test`); rerun alone, it passed.
- Owner decisions open: merge `result-records` to main (needs your go); design §8 questions (permissionless seal, template id in the run receipt, tree seals); whether to design mixed regions inside one template now.
- 10-15 (owner: merge to main; design mixed regions now): `result-records` fast-forwarded into main at 6be923f (local, main 8 ahead of origin, not pushed). Design `docs/design/mixed-mode-pipelines-v1.md` on local branch `mixed-mode-pipelines`: mixed regions as pipelines of single-mode stages bound by `ResultRef`s; three slices (imported inputs for v2.1 runs, consensus v2.1 runs, pipelines), about 6.5-8.5 weeks estimated; owner decisions in its §11.
- 10-15 (owner): mode results §8 answered, all folded into pipelines slice 1 (design §3.4): anyone may seal (only the authority aborts), receipts `D21Q` carry the template id, tree seals `STATE_TREE_V1` (chunked-value digest, state imports as a chunked input). Slice 1 now about 3-4 weeks. Open: pipelines §11 decisions 1-5 and the go to build. Freed 7.9 GB (DCG debug build cache) when free disk fell to 1.1 GB from other jobs on the Mac.
- 10-16 (owner): per-kernel modes chosen by the executor evaluated and deferred (design §12: sound in one tree, but no cost, finality or privacy upside with today's modes; Freivalds for 4B decode is never a saving on chain). Slice 2 reserves the mode fields.
- 10-16 (owner): every pipelines §11 recommendation accepted (stages, slice 1 first, consensus v2.1 runs, test image then trial); template ids take the mode field through a new id domain dcg.template.id.v2.2 (option A). Open: the go to build slice 1. DCG main, dcg-doom (e209fae, deployment details moved to an ignored local env file) and Basanos main pushed.
- 10-16 (owner: go to build slice 1): branch `slice1-imports` (local), feature `pipelines-v1`, commits e8cde37..1231cc0. A: `D21Q` receipts (380 bytes: template id, kind, windows, bonds; `read_run_result` takes an optional template; init funds the receipt; underfunded runs close into `D21P`). B: anyone may seal (only the authority aborts); found and fixed while building: anyone could trim a kernel-halted session before its seal and deny its result, so until the seal its state and resource closes need the authority's signature. C: tree seals (`ANCHOR_OP_TREE_SEAL`, `STATE_TREE_V1`, chunked-value digest, frontier in a 704-byte anchor account). D: imported inputs (import table in the template create data, bound by the id; `DRQ1` requirements; version-2 runs; `IMPORT` sub 29 from a run output or a tree-sealed state; commit waits). Design change from §3.1 as written: imports live in the template, not the spec tree (the id is the hash of the create data); single-chunk state imports deferred (a chunk does not fit a transaction). Without the feature the alpha image is the same size (344,304) but not byte-identical to main's 1da74d34 (code layout shifts); the import paths are compiled out. Fuzz campaigns with the feature clean (1050, 1051). Full suites and a rule-10 review in progress.
- 10-16 later: rule-10 review of slice 1: no critical; H1 (a stranger fixed the seal form), H2 (anyone could trim a sealed session), M1 (tree-seal compute), M2 (weak import requirements) and lows, all fixed in cb27315 (kernel-declared open seal form; authority-signed state closes for kernel halts, sealed or not; IMPORT refuses requirements that do not name the computation). Measured on SBF: a 64 KiB tree-seal chunk 533,329 CU at 2^6, 46,431 at 2^16. After the fixes: plain 85, v2.1 83 and with the feature 87, SBF feature suite 133, SBF with pipelines and graph-v21 222, Python 370 (5 skipped), all passing. Not yet rerun after the fixes (stopped by the 5 GB disk floor; other jobs on the Mac fill the disk): v2.1 SBF suite with the feature (passed 77 before the fixes), composed-app example (native passed before), fuzz campaign 1052. Merge to main waits for those.
