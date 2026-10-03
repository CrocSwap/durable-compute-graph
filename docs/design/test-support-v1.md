# `dcg-test-support`: a real-flow state builder for program tests (draft, 2026-10-02)

**Status: draft.** The owner decided on 2026-10-02 that this would be a crate,
so Basanos uses it too. Rule source: Basanos `docs/project-rules.md` rule 6.

## Why

Revision-8 tests reach mid-protocol states by writing account bytes
directly. The 2026-10-02 inventory counted 125 direct writes in DCG's
`unified_v8_document.rs` alone, and 57 in Basanos's copy of it. Those writes
encode layouts and addressing rules. When DCG core tightened both (records at
derived addresses, newer record versions), the copies broke, and nothing
connected them to the rule they were simulating. Duplicated tests across the
two repos drifted the same way.

## Principles

1. **States come from real instructions.** The builder reaches each state by
   sending the instructions that create it. A test asks for a state; it does
   not write one.
2. **Fixtures come from real pipelines.** Retained PT2P and PT1X artifacts,
   registry census rows and compiled plans are real-run outputs (rule 6).
   The builder loads them and seals them through the real upload, seal and
   admission instructions. It never installs their accounts directly.
3. **Forbidden states come from legacy modes.** A state the current program
   refuses to create, such as a record from before a newer check, is made by
   compiling the program with a named, test-only `legacy-*` feature that
   restores the older behavior, and then running the real flow. Existing
   example: `test-rev8-before-payer-alias-fix` (to be renamed into this scheme).
4. **One home per test.** DCG-core behavior is tested in DCG. Basanos tests
   its kernels, its tags (120–129, 146, 199, 200), the hybrid split and
   end-to-end integration, using this crate.

## Crate shape

`crates/dcg-test-support` (`publish = false`, a workspace member, used as a
dev-dependency). Its Solana dependencies are pinned to dcg-program's
versions.

- **`Target`**: the program under test, given as a program id plus either a
  native processor function or an SBF image (directory and `.so` name).
  - DCG passes `dcg_program::process_instruction` or `dcg_program.so`.
  - Basanos passes its hybrid `process_instruction` or `basanos_dcg_program.so`.
- **`Chain`**: wraps `ProgramTestContext`. It provides:
  - funded actors (admitter, executor, challenger, payer);
  - `send` (each transaction is made unique, so equal bodies never collide);
  - `send_fresh`;
  - typed refusal helpers (`custom(code)`);
  - account readback;
  - compute-unit capture;
  - slot warps through the clock sysvar.
- **`Fixtures`**: loads the retained artifact roots (the `BASANOS_PT2P_*`
  environment variables, with the defaults the suites already use) and
  reports clearly when a root is missing.
- **The staged builder.** Each stage consumes the previous handle and returns
  typed handles to real accounts:

  ```text
  Template      registry (create, write, freeze), PT1X and PT2S upload and seal, admission
    -> Document     UnifiedInit with a Binding2, its option table and Terms2
    -> Landed       position roots landed
    -> Finalized    finalize
    -> Attested     chosen outputs attested (honest values, or chosen cells through rekey)
    -> Challenge    opened by tag 166/168/169 with real proofs, on a chosen entry
    -> Responding / Ruled / Settled / Closed
  ```

  Every stage has its own test that it produces exactly the state it claims.
  Tests that need several documents on one template reuse the `Template`
  handle.

## Open questions

- **Adversarial corruption of program-owned accounts: decided (b), 2026-10-02.**
  A refusal test is written as the attack an adversary could actually make on
  chain: it passes a different *real* account in the slot. Examples: a
  record of the wrong kind, a stale record from an earlier run, a second
  instance, or another template's record, each created by the builder. A
  corruption that no instruction-level attack can produce, meaning bytes
  only the program could have written wrongly, is not tested by patching.
  If it is worth keeping as defense in depth, it becomes a unit test of the
  parsing function.
- **How far down the stages to go before migrating.** The plan is the stages
  the inventory shows tests actually need, nothing speculative.

## Owner decisions at the inventory checkpoint (2026-10-02)

The inventory (Basanos `out/runs/test-harness-2026-10-02/inventory-sites.md`)
found 301 direct account writes: 102 phase skips, 98 corruptions, 31
environment, 19 fixture installs, 19 legacy, 18 other and 10 side-effect
patches. 43 of the Basanos document tests are identical copies of DCG tests.

1. **Snapshots of expensive real states are allowed.** A state that is slow
   to reach (a K=10,240 admission, 10,240 attestations) is produced once by
   the builder's real flow and saved. Tests load the saved accounts. A
   regeneration check rebuilds each snapshot and requires byte equality, so
   a snapshot can never drift from what the program produces.
2. **Revision-7 compatibility tests are dropped.** They covered how the
   revision-8 program treats revision-7 records. No legacy revision-7 mode is
   built.
3. **Corruptions:** the ones an attacker can actually produce on chain (a
   stale record, a second copy, another template's record, a wrong account in
   a slot) become integration tests with real accounts from the builder.
   Corruptions only the program could write (wrong magic, truncation,
   counters at their maximum, forged FINAL records, inconsistent bitmaps)
   become unit tests of the reader for that record. Integration tests focus
   on what an attacker can do.
