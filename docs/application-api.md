# DCG application API

This note documents the initial static app-instruction and region-commitment
surface. It does not add an account-address policy or move application kernels
into DCG.

## Static instruction registration

`dcg_program::app_api` exposes:

- `ApplicationInstruction`, containing a wire tag, stable handler id,
  non-zero semantic version, preflight function, and handler function;
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
revision-8 core set. The public `validate_application_tags` function applies
the same const-time rules to a tag list; its documentation includes two
compile-fail examples for duplicate app tags and overlap with tag 125.

At runtime, an empty instruction byte array is refused. A core tag is sent to
`process_instruction_with_manifest` with the wrapped kernel/form manifest. A
non-core tag is looked up in the sorted app table; its preflight runs before
its handler. A tag owned by neither table returns
`ProgramError::InvalidInstructionData`. The legacy
`process_instruction_with_manifest` and `process_instruction` entry points
remain available for DCG-only callers and retain their existing dispatch
behavior.

The revision-8 core set includes the tags currently routed by DCG's root
dispatcher and excludes the app dispute/replay family 120–124 and 126–129.
Tag 125 is retained by DCG. The test-only workload tags are not members of the
wire-revision set.

### Preflight and account context

Preflight receives untrusted instruction bytes and the original ordered
accounts. It is responsible for parsing the complete instruction and checking
the tag-specific roles, bounds, aliases, and address derivations before it
returns success. A program-owned account is not validated by owner equality
alone, and the derivation seed must come from an independently validated
parent record or instruction identity.

`CheckedApplicationAccounts` is currently a small borrowed view created after
the callback succeeds. Its construction contains a TODO for the shared
account-address rule helper from the separate `dcg-address-rule-fix` change;
that helper's final API is intentionally not guessed here. Until the helper is
merged and wired into this context, the wrapper is not evidence that DCG has
independently checked an app account address. The app callback contract must
not be used to claim the pending common address rule.

### Program identity

`ApplicationProgramManifest::identity_digest()` uses the versioned
`dcg/application-program-manifest/1` domain. It commits:

1. `ApplicationManifest::identity_digest()` (application id and version);
2. `ApplicationManifest::admission_identity_digest()` (including its static
   form-to-kernel bindings);
3. the table length and each ascending `(tag, handler id, handler version)`
   row, with length-prefixed UTF-8 handler ids and little-endian integers.

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
