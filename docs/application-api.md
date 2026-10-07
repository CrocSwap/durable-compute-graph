# DCG application API

This note documents the static app-instruction surface.
Application handlers remain app code, while the dispatcher validates declared
account provenance before calling application code.

## Static instruction registration

`dcg_program::app_api` exposes:

- `ApplicationInstruction`, containing a wire tag, stable handler id,
  non-zero semantic version, per-account address/role rules, preflight
  function, and handler function;
- `ApplicationProgramManifest`, which wraps a static
  `kernel::ApplicationManifest` and a statically allocated instruction array;
- `ApplicationAccountCheckContext`, passed only to preflight with the invoked
  program id, tag, complete instruction bytes, and raw ordered `AccountInfo`
  slice;
- `ApplicationInstructionContext`, carrying only handler invocation metadata
  after preflight;
- `CheckedApplicationAccounts`, the borrowed ordered account view passed to a
  handler after preflight succeeds;
- `process_instruction_with_application`, the core-first dispatcher;
- `CORE_INSTRUCTION_TAGS_REVISION_8` and its const membership helper: the
  tags reserved to DCG.

Construct an entry with `ApplicationInstruction::new` and the array-valued
`ApplicationProgramManifest::new`. (The revision-8 dispute and artifact hooks,
and `new_with_dispute_hooks`, were removed with revision 8; see
`CHANGELOG.md`.) The constructor validates at compile time
that application tags are strictly ascending, unique, and disjoint from the
DCG core tag set, PDA seed prefixes, and app-owned account kinds. App PDA
seeds begin with the application id, which must contain 1–32 bytes; the id may
not appear again in the seed list. `ProgramKey` may not source its key from
instruction bytes. Program-owned `ProgramPda` and `ProgramKey` kinds require a
non-empty magic that does not prefix or share a prefix with a DCG core magic.
`process_instruction_with_application` takes a
`&'static ApplicationProgramManifest`, so production dispatch must use the
validated static value and collision checks run during compilation. The public
`validate_application_tags` function applies the same const-time rules to a
tag list; its documentation includes compile-fail examples for duplicate app
tags, overlap with tag 125, and a collision routed through `new`. Compile-fail
examples also cover a missing app-id PDA prefix, a `ProgramKey` instruction
source, and empty or core-overlapping magic.

At runtime, an empty instruction byte array is refused. A core tag is sent to
`process_instruction_with_manifest` with the wrapped kernel manifest. Other
tags are looked up in the sorted app table; their DCG account rules run before
preflight, and preflight runs before the handler. A tag absent from the app
table falls back to the core dispatcher, preserving feature-gated and future
core routes. The `process_instruction_with_manifest` and `process_instruction`
entry points remain available for DCG-only callers.

The core tag set holds the tags DCG routes or reserves: the retired
revision-8 tags 115-200 (refused, kept so an application cannot reuse a
historical tag number) and the graph tags 208-227. The test-only workload
tags are not members of the set.

### Preflight and account context

Each instruction rule covers one ordered account. Its identity is an exact key
with an optional owner constraint, a program-owned PDA, a program-owned exact
key, or a system-owned PDA. `ExactKey` refuses an account owned by the current DCG
program, even if its key and optional owner constraint match. Key sources can
be fixed, read from instruction bytes, derived from a required signer, or
taken from an earlier account that has already passed its rule; `ProgramKey`
is restricted to the fixed, signer, or validated-account sources. PDA seeds
can use the app-id prefix, fixed byte strings, instruction-data slices, or
validated earlier account keys. Every rule also declares minimum
writable/signer privileges and an optional writable alias group. DCG validates
the full rule array before calling application code. A program-owned account
is not validated by owner equality alone, and a PDA seed must come from an
independently validated parent, signer, fixed value, or checked instruction
identity.

`CoreRecord` and `StoredBumpPda` read revision-8 records. They are retired
with revision 8: a manifest that names either fails to build, and the runtime
refuses them too. They are removed in the next release.

`CheckedApplicationAccounts` is a borrowed ordered view available to a handler
only after DCG validates every account rule and the application preflight
returns success. The rules are included in the manifest identity digest, so
changing address or role policy changes the committed app identity. An
application that owns its Solana entrypoint can call a lower-level DCG function
or bypass this dispatcher entirely; it must route every entrypoint through
`process_instruction_with_application` to receive these checks.

### Program identity

`ApplicationProgramManifest::identity_digest()` uses the versioned
`dcg/application-program-manifest/3` domain. It commits:

1. `ApplicationManifest::identity_digest()` (application id and version);
2. `ApplicationManifest::admission_identity_digest()` (its retired
   form-to-kernel fields, now always empty, so existing identities do not
   move);
3. the table length and each ascending `(tag, handler id, handler version)`
   row, with length-prefixed UTF-8 handler ids and little-endian integers;
4. each instruction's ordered account rules, including identity source, PDA
   seeds, account shape, roles, and alias group.

Function addresses are not identity fields. If a handler's behavior changes,
increment its semantic version or the application version. Keep this manifest
identity alongside source, feature, toolchain, image-hash, and program-address
records for an assembled image; none of those identities substitutes for the
others.
