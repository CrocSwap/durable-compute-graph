# v2.1 account writer provenance audit (2026-10-03)

Scope: writers newly reported by `account_provenance_lint` in
`crates/dcg-program/src/disputes_v21.rs` and `graph_v2.rs` at DCG `a1bc8cc`,
plus two previously unallowlisted `closure_v2_generic.rs` helpers exposed by
the same lint run.
This is a source audit of the native program, not a deployed-image claim.
The lint names functions without an in-function gate; its allowlist is an
inventory of reviewed callers, not a proof by itself.

## Shared checks used below

In `disputes_v21.rs`, `create_pda` (179-206) checks the derived key and bump,
requires an empty system-owned target, funds rent from its caller's signed
payer, then allocates and assigns the exact requested size. Its callers pass
the `dcg21tmpl` (556-559), `dcg21run` (627-632), `dcg21dsp` (716-728),
`dcg21rc` (852-869), or `dcg21stg` (925-945) seeds. `template` (308-335)
checks owner, exact legacy/tracked size, D21T and the template PDA;
`run_checked` (428-434) checks D21R, minimum size, template key, owner and
run PDA; `dispute_ctx` (750-761) checks those two records plus exact D21D
size, magic, run key, owner and dispute PDA. `staging_role` (1002-1009)
checks the stage header, D21S, dispute key, owner and stage PDA. These
checks precede every listed dependent write. PDA keys prevent substitution
of a signer account or another program-owned record.

In `graph_v2.rs`, `create_pda` (113-143) checks the derived key and bump,
requires an empty system-owned target, and uses the caller's signed payer to
fund and assign the requested size. `template_view` (462-477) checks owner,
minimum size, DCT2 and template PDA; `run_checked` (519-526) checks owner,
minimum size, DCR2, template key and run PDA; `dispute_checked` (841-847)
checks owner, DCD2 and dispute PDA. Creators allocate exact sizes at
`blob_create` (197-218), `admit_template` (327-389), `init_run` (488-516)
and `commit_root` (995-1037). There is no graph v2 dispute size check in
`dispute_checked`; only the keyed creator can initialize that PDA, and no
reviewed route resizes it. This is a source invariant, not an explicit
length guard.

## Writer inventory

Each row cites the writer's first line and any extra guard beyond the shared
checks above. “Confirmed” means the source traces the written account to a
checked PDA, with role authorization and shape checked at creation or read.
Permissionless transitions are marked as such; their state predicates and
recorded payout keys supply authorization.

| Writer | Additional pre-write check | Verdict |
|---|---|---|
| `disputes_v21.rs:171 create_pda` | Caller-signed payer; exact seeds/bump, empty system owner and rent/size at 179-206. | Confirmed |
| `disputes_v21.rs:384 change_template_run_count` | Only `init_run` (601-609, 646-648) and `close_run` (1958-1964, 1986-1989) call it after `template`; tracked D21O size/magic and writable flag at 385-390. | Confirmed |
| `disputes_v21.rs:654 commit` | `template`/`run_checked` at 656-657; recorded executor signer, open status, deadline and root binding at 658-675. | Confirmed |
| `disputes_v21.rs:876 cache_answer` | `dispute_ctx` at 878; cache D21C size/magic and derived node PDA at 885-890. Permissionless reuse of verified cache. | Confirmed |
| `disputes_v21.rs:902 pick` | `dispute_ctx` at 904; challenger signer, phase and pickable child at 906-913. | Confirmed |
| `disputes_v21.rs:950 stage_grow` | `dispute_ctx`/`staging_role` at 952-954; signed funder and bounded length at 955-964. | Confirmed |
| `disputes_v21.rs:969 stage_write` | `dispute_ctx`/`staging_role` at 971-973; role signer and bounds at 974-988. | Confirmed |
| `disputes_v21.rs:1121 reveal_leaf` | `dispute_ctx`/executor signer at 1123-1124; phase, size and committed leaf hash at 1139-1164. | Confirmed |
| `disputes_v21.rs:1697 rule` | Only the authenticated `Ctx` reaches this helper from claim/timeout; open ruling, recorded challenger/executor keys and run status at 1711-1733. | Confirmed |
| `disputes_v21.rs:1753 move_lamports` | Callers pass checked run/dispute/template PDAs; recipient keys checked in `rule` (1715, 1728), `moot` (1813), `pay_pot` (1843-1845), `finalize` (1865), and close paths (1918-1919, 1968). Checked arithmetic at 1754-1755. | Confirmed |
| `disputes_v21.rs:1786 advance` | `dispute_ctx` at 1788; ruled dispute sequence equals run prefix at 1789-1798. Permissionless progress. | Confirmed |
| `disputes_v21.rs:1804 moot` | `dispute_ctx` at 1806; refuted status, sequence and recorded challenger key at 1808-1818. Permissionless refund to that key. | Confirmed |
| `disputes_v21.rs:1831 pay_pot` | `dispute_ctx` at 1833; best-win/prefix/paid checks and both recorded payee keys at 1838-1848. Permissionless payout. | Confirmed |
| `disputes_v21.rs:1857 finalize` | `template`/`run_checked` at 1859-1860; terminal deadline, zero open disputes and recorded executor key at 1861-1871. | Confirmed |
| `disputes_v21.rs:1883 close_into` | All callers first authenticate the target: `close_dispute` (1910-1939), `close_run` (1958-1992), `close_template` (2013-2027), `close_cache` (2056-2085). Both accounts writable and distinct at 1884-1890. | Confirmed |
| `disputes_v21.rs:1906 close_dispute` | `dispute_ctx` at 1910; ruling, prefix and recorded recipient keys at 1914-1921; stage PDA, owner, D21S, role and dispute key at 1924-1939. | Confirmed |
| `disputes_v21.rs:1956 close_run` | `run_checked`/`template` at 1958-1960; payer key, expiry or settled/closed state at 1968-1984; tracked count shape at 1961-1964. | Confirmed |
| `disputes_v21.rs:2033 retire_template` | `template`/tracked shape at 2038-2040; recorded payer signer and not-retired state at 2035, 2042-2046. | Confirmed |
| `graph_v2.rs:105 create_pda` | Caller-signed payer; exact seeds/bump, empty system owner and rent/size at 113-143. | Confirmed |
| `graph_v2.rs:222 blob_write` | Owner and writer signer at 224-227; **no blob PDA or header-size check**, unlike `sealed_blob` at 270-278. | Finding |
| `graph_v2.rs:243 blob_seal` | Owner, writer signer, DCB2 and exact length at 245-255; **no blob PDA check**. | Finding |
| `graph_v2.rs:545 execute` | `template_view`/`run_checked` at 550-551; signed caller, consensus mode and open status at 547-559. Table key comes from checked template at 480-484. | Confirmed |
| `graph_v2.rs:575 commit` | `template_view`/`run_checked` at 580-581; executor signer, optimistic mode, open status and trace size at 577-596. | Confirmed |
| `graph_v2.rs:613 take_bond` | Callers authenticate run/dispute PDA (`challenge` 642-643, `finalize` 674-675, `rule_*` through checked callers); recipient is the proof-bearing challenger/auditor or recorded executor, with writable check at 617-622. | Confirmed |
| `graph_v2.rs:637 challenge` | `template_view`/`run_checked` at 642-643; challenger signer, window and wrong-step proof at 639-663. | Confirmed |
| `graph_v2.rs:672 finalize` | `template_view`/`run_checked` at 674-675; deadline, status and recorded executor key at 676-694. | Confirmed |
| `graph_v2.rs:700 sample_audit` | `template_view`/`run_checked` at 707-708; canonical slot-hashes key, sampling mode, post-commit entropy and wrong-step proof at 704-737. Permissionless audit reward. | Confirmed |
| `graph_v2.rs:747 close_run` | `run_checked` at 749; terminal/open state and recorded payer signer at 751-762. | Confirmed |
| `graph_v2.rs:769 raw_write` | Owner and signer at 771-773, bounds at 775-782; **no PDA, size or discriminator by design** under `graph-v2-raw-write`. | Finding |
| `graph_v2.rs:954 rule_challenger` | Checked run/dispute callers (`replay_leaf` 1183, `settle_descent` 1338-1341); recorded challenger key at 956-960. | Confirmed |
| `graph_v2.rs:976 rule_executor` | Same checked callers; recorded executor key before bond transfer at 983-989. | Confirmed |
| `graph_v2.rs:1046 open_dispute` | `template_view`/`run_checked`/`dispute_checked` at 1051-1053; challenger signer, committed root mode, window and idle phase at 1048-1064. | Confirmed |
| `graph_v2.rs:1083 reveal_region` | Checked run/dispute at 1085-1087; executor signer, phase, committed root and plan/run/region binding at 1089-1107. | Confirmed |
| `graph_v2.rs:1121 choose` | Checked run/dispute at 1123-1125; recorded challenger signer, phase and selected child at 1126-1149. | Confirmed |
| `graph_v2.rs:1155 reveal_leaf` | Checked run/dispute at 1157-1159; executor signer, phase and step-root path at 1161-1173. | Confirmed |
| `graph_v2.rs:1334 settle_descent` | Checked run/dispute at 1338-1341; phase/deadline and recorded payee keys at 1343-1359. Permissionless timeout. | Confirmed |
| `closure_v2_generic.rs` legacy ruling | `live` refuses v2/v4 without `legacy-hclosure-handlers` and derives the challenge PDA when that feature is enabled. `execute` calls `live` and validates the document before its inlined ruling. | Resolved (lint 4/4) |
| `closure_v2_generic.rs:2110 rule_v6` | `execute` checks v5 DCR1 exact size, kind, owner, seeds and stored bump at 1964 and 120-174; v6 DCM2 exact size, kind, owner and descriptor-derived PDA at 1985 and 234-260. | Confirmed |

## Findings and concrete substitution

1. `blob_write` accepts any program-owned account whose bytes claim DCB2 and
   name the writer; it does not derive `dcg2blob` from kind and ID. It also
   slices bytes 44..76 before checking the account's length, so a short
   program-owned account reaches an out-of-bounds panic. With the test-only
   `graph-v2-raw-write` route enabled, a signer can create a program-owned
   keypair account, write a forged DCB2 header with `raw_write`, then pass that
   **non-PDA** account to `blob_write` instead of a blob PDA. This demonstrates
   account substitution at the writer; no downstream acceptance of that fake
   blob was established, because `sealed_blob` checks the PDA.
2. The same forged non-PDA DCB2 account can be passed to `blob_seal` after
   setting an ID equal to its content digest. `blob_seal` changes its sealed
   flag without deriving the blob PDA. Again, `sealed_blob` later checks the
   PDA, so this is a writer-provenance gap, not a demonstrated downstream
   protocol bypass.
3. `raw_write` is explicitly a signer-authorized arbitrary program-owned
   keypair write under a test-only feature. Its lack of PDA and discriminator
   means it cannot satisfy this task's writer criterion. A signer can use it
   to place DCB2 bytes in a non-PDA program account as in findings 1-2. Keep
   it out of a PDA writer allowlist; the route should remain excluded from
   production images.
4. `rule_legacy` is reached after `live` accepts a version-2 or version-4
   DCR1 account based on owner, 8,192-byte size, magic, version, phase and
   deadline, without checking a challenge PDA (120-145). A signer can create
   a program-owned keypair account and, if the test-only raw-write feature is
   present, place a forged legacy DCR1 header there. That substitute passes
   `live` and can be used to enter the legacy execute path; the document is
   independently PDA-checked, so an end-to-end false ruling is not established
   by this source audit. The code fix is to validate the legacy challenge's
   version-specific PDA in `live`, or retire those versions in a new image.

No program behavior was changed. The four findings remain absent from the
reviewed writer snapshot, so the lint is expected to remain red for them.

## L4b follow-up (source reachability)

`graph_v2::blob_write` and `blob_seal` now check the DCB2 header length and
derive `dcg2blob` from the stored kind and ID before writing. The lint keeps
`raw_write` in a separate test-only exemption list, never in the PDA writer
allowlist. The legacy ruling is now guarded in `live`. The source lint passed 4/4 without an exemption for `rule_legacy`.

The Basanos switchover assembly pins DCG `9ec8d6a`, which predates the
`revision-8-lifecycle` tag gate in this review branch. Its dispatcher sends
tag 140 to DCG core. Exact route to chosen bytes in a non-PDA program-owned
account, without raw-write:

1. Create and fund a zeroed signer-owned PT1X state account and three nonzero
   system-owned keypair byte accounts; make one byte account 8,192 bytes.
2. Call tag 140 (`pt1_onchain::init_fresh`) with all four account signers and
   the system program. It assigns the three byte accounts to the program and
   records their keys and lengths in the PT1X state.
3. Call tag 141 (`pt1_onchain::upload`) in 900-byte chunks, with the recorded
   authority signer and byte account. It copies the supplied bytes into that
   program-owned keypair account, with no PDA check on the byte account. Put a
   chosen DCR1 v2/v4 header and 8,192-byte body there.
4. `closure_v2_generic::live` accepts a v2/v4 DCR1 by owner, size, magic,
   version, phase, deadline, and supported form, without deriving its key.

This proves a production-image route to the forged record bytes, not an
end-to-end false ruling: `execute` separately validates the document and
response. `desc_upload::process_upload` is another owner-and-bytes writer in
source, but no production dispatcher calls its handlers. In the later DCG
review branch, `revision-8-lifecycle` gates tags 115–200; that gate does not
exist at the pinned switchover commit. The deployed shared testnet image in
`docs/hello-graph.md` also contains raw-write and cannot establish a raw-free
production precondition. The no-raw guard covers the DCG review branch's
default feature set, the Basanos manifest's selected features, and the next
declared shared testnet feature set; it does not erase the pinned-code route.

## Native verification

- Measured: `CARGO_BUILD_JOBS=3 cargo test --profile fasttest -p dcg-program
  --features graph-v21 --test account_provenance_lint
  source_audit_matches_the_reviewed_writer_allowlist -- --exact --nocapture`
  failed with the three graph findings and both `closure_v2_generic` helpers
  missing from the snapshot. After that single lint run, `rule_v6` was added
  to the snapshot; the expected four remaining differences were not rerun.
- Measured: `CARGO_BUILD_JOBS=3 cargo test --profile fasttest -p dcg-program
  --features graph-v21 --test disputes_v21_skeleton --quiet` passed 21/21.
  This is a native ProgramTest check, not SBF or live-validator verification.

## Legacy DCR1 closure (2026-10-03)

The Basanos switchover revision-8 image now refuses DCR1 v2/v4 at `live` with
error 742. DCG core refuses those versions by default; the named legacy feature
requires the descriptor/challenger/nonce-derived challenge PDA. Both implementations
check the v5 challenge PDA, and Basanos also compares the stored bump. The uploaded
keypair PoC is retained as a tag-124 regression for v2, v4 and v5. This closes the
forged-record entry point; the older document check had already prevented a
false ruling in the investigated revision-8 image.

Permissionless call ordering: an executor who calls `execute` first can obtain
the honest ruling only after all committed proofs are complete. A challenger who
calls first with a forged record now receives a refusal and cannot set a winner.
The payer gains no refund or priority from a refused call. A bystander can call
first only on an authenticated live challenge with complete proofs; the recorded
winner and payout addresses control the result, so the bystander gains no bond.
Timeout, moot and close handlers do not call this legacy `execute` ruling helper;
they keep their existing authenticated record checks.
