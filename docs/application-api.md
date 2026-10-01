# DCG application API

This note documents the static app-instruction and region-commitment surface.
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
- `CORE_INSTRUCTION_TAGS_REVISION_8` and its const membership helper.

Construct an entry with `ApplicationInstruction::new` and the array-valued
`ApplicationProgramManifest::new`. The constructor validates at compile time
that application tags are strictly ascending, unique, and disjoint from the
revision-8 core set. `process_instruction_with_application` takes a
`&'static ApplicationProgramManifest`, so production dispatch must use the
validated static value and collision checks run during compilation. The public
`validate_application_tags` function applies the same const-time rules to a
tag list; its documentation includes compile-fail examples for duplicate app
tags, overlap with tag 125, and a collision routed through `new`.

At runtime, an empty instruction byte array is refused. A core tag is sent to
`process_instruction_with_manifest` with the wrapped kernel/form manifest. A
non-core tag is looked up in the sorted app table; its DCG account rules run
before preflight, and preflight runs before the handler. A tag absent from the
app table falls back to the core dispatcher, preserving feature-gated and
future core routes. The legacy
`process_instruction_with_manifest` and `process_instruction` entry points
remain available for DCG-only callers and retain their existing dispatch
behavior.

The revision-8 core set includes the tags currently routed by DCG's root
dispatcher and excludes the app dispute/replay family 120–124 and 126–129.
Tag 125 is retained by DCG. The test-only workload tags are not members of the
wire-revision set.

### Preflight and account context

Each instruction rule covers one ordered account. Its identity is an exact key
with an optional owner constraint, a program-owned PDA, a program-owned exact
key, or a system-owned PDA. Key sources can be fixed, read from instruction
bytes, derived from a required signer, or taken from an earlier account that
has already passed its rule. PDA seeds can use fixed byte strings,
instruction-data slices, or validated earlier account keys. Every rule also
declares minimum writable/signer privileges and an optional writable alias
group. DCG validates the full rule array before calling application code. A
program-owned account is not validated by owner equality alone, and a PDA seed
must come from an independently validated parent, signer, fixed value, or
checked instruction identity.

`CheckedApplicationAccounts` is a borrowed ordered view available to a handler
only after DCG validates every account rule and the application preflight
returns success. The rules are included in the manifest identity digest, so
changing address or role policy changes the committed app identity. An
application that owns its Solana entrypoint can call a lower-level DCG function
or bypass this dispatcher entirely; it must route every entrypoint through
`process_instruction_with_application` to receive these checks.

### Program identity

`ApplicationProgramManifest::identity_digest()` uses the versioned
`dcg/application-program-manifest/2` domain. It commits:

1. `ApplicationManifest::identity_digest()` (application id and version);
2. `ApplicationManifest::admission_identity_digest()` (including its static
   form-to-kernel bindings);
3. the table length and each ascending `(tag, handler id, handler version)`
   row, with length-prefixed UTF-8 handler ids and little-endian integers;
4. each instruction's ordered account rules, including identity source, PDA
   seeds, account shape, roles, and alias group.

Function addresses are not identity fields. If a handler's behavior changes,
increment its semantic version or the application version. Keep this manifest
identity alongside source, feature, toolchain, image-hash, and program-address
records for an assembled image; none of those identities substitutes for the
others.

The static instruction table does not replace `ApplicationHooks` or
`DecisionRouteSelector`. Those remain the existing manifest's revision-8
policy and typed-decision interfaces. The generic app dispute-hook and
artifact-verifier contract is a separate handler-API prerequisite.

## Region-content commitments

`dcg_program::region_commitment` exposes two pure v1 functions:

```rust
pub const REGION_CONTENT_DOMAIN_V1: &[u8] = b"basanos/dcg-region-content/1";

pub fn seed_v1(
    region_id: u16,
    region_byte_length: u64,
    account_count: u32,
) -> [u8; 32];

pub fn fold_account_v1(
    running: &[u8; 32],
    region_offset: u64,
    account_byte_length: u64,
    account_content_digest: &[u8; 32],
) -> [u8; 32];
```

The seed hashes the domain followed by the region id (`u16` LE), region byte
length (`u64` LE), and account count (`u32` LE). Each fold hashes the same
domain, running root, region offset (`u64` LE), account byte length (`u64` LE),
and 32-byte account-content digest. These bytes match Basanos's existing
`region_content_seed` and `fold_account` exactly.

The shared vector file is
[`tests/golden/dcg/lifecycle/region_content_v1.tsv`](../tests/golden/dcg/lifecycle/region_content_v1.tsv).
Tests regenerate its deterministic account bodies and account-content folds,
then compare the 84-account, reordered, repartitioned, and single-account
roots. DRS1 state, address derivation, tags 14–15, and supplied-window
handling are outside this module.
