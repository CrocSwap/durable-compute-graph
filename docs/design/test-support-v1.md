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

- **Adversarial corruption of program-owned accounts.** Some refusal tests
  replace or corrupt an account only the program can write, for example a
  wrong-kind or stale record. Such a state is unreachable on chain. Should
  these tests:
  - (a) be dropped;
  - (b) be expressed as instruction-level attacks (pass a different real account in the slot); or
  - (c) be kept through a named, documented `Chain::inject_fault`?

  The inventory counts them; the owner decides.
- **How far down the stages to go before migrating.** The plan is the stages
  the inventory shows tests actually need, nothing speculative.
