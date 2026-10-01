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
  `kernel::ApplicationManifest`, a statically allocated instruction array,
  and application dispute/artifact hooks;
- `ApplicationDisputeHooks`, the application form catalog and PT1 replay
  adapter used when generic dispute execution is enabled;
- `ArtifactWitnessVerifier`, the application-owned verifier for model
  descriptor, weight-row, artifact-block, and supplied-read commitments;
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
`ApplicationProgramManifest::new`, or use
`ApplicationProgramManifest::new_with_dispute_hooks` to provide static
`ApplicationDisputeHooks` and `ArtifactWitnessVerifier` implementations. The
plain `new` constructor installs fail-closed adapters for both hook traits.
The constructor validates at compile time
that application tags are strictly ascending, unique, and disjoint from the
revision-8 core set, PDA seed prefixes, and app-owned account kinds. App PDA
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
`process_instruction_with_manifest` with the wrapped kernel/form manifest.
Generic dispute tags 120–124 and 126–129 are sent to
`closure_v2_generic::process_generic_dispute_tag`. Tags 122, 123, and 127
delegate artifact interpretation to `ArtifactWitnessVerifier`; tag 124 calls
the application's replay hook before comparing committed writes and ruling;
tag 129 verifies a bounded unified range-read continuation. These tags bypass
ordinary app handlers; applications supply their form and artifact behavior
through the dispute hooks.
Other non-core tags are looked up in the sorted app table; their DCG account
rules run before preflight, and preflight runs before the handler. A tag absent
from the app table falls back to the core dispatcher, preserving feature-gated
and future core routes. The legacy
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
key, a system-owned PDA, a DCG core record, or a DCR1 response PDA validated
with its stored bump. `ExactKey` refuses an account owned by the current DCG
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

`CoreRecord` calls DCG's own revision-8 DCM2 or DCR1 reader with a read-only
role. `StoredBumpPda` currently accepts only the DRU1 PDA derived from a prior
read-only validated DCR1 v5/v6 record and its stable response bump at byte 219.
These variants let an app handler refer to core records without duplicating
their parsing or treating an unvalidated stored byte as a bump.

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
policy and typed-decision interfaces. `ApplicationDisputeHooks` and
`ArtifactWitnessVerifier` isolate application form replay and model-artifact
semantics from the generic DCR1/DRU1 state transitions. The generic engine
accepts unified DCR1 v5 with DCM2 v6 or v7. Its shared record and document
validators also accept DCR1 v2/v4 with their legacy DCM2 formats on the
hook-backed paths. Full v2/v4 tag-120/121 replay, tag-124 chunked output
replay, and legacy tag-129 page-pick continuation are not yet ported.
Unsupported application forms return custom 740 before a tag reads its
response or document accounts. The test application used by the generic SBF
suite is a mechanics harness around ByteSum; it is not a production form
catalog or model adapter.

For tags 120, 121, and 128, DCR1/DRU1 identity failures pass through DCG's
shared provenance gate and return custom refusal 734; the Basanos response
reader used custom 731 for some DRU1 owner/address failures. Tag 126 already
used proof refusal 734 for a response-address mismatch. The same mapping
applies to the new tags where they validate DCR1/DRU1 identity. Basanos's
older owner-only DCR1 checks can also surface `IncorrectProgramId`, while DCG
maps an identity-gate failure to custom 734. Application hook refusals are
passed through as returned, so their parity depends on the selected app
adapter. These code mappings are part of the documented account-provenance
seam. Per-tag code lists and SBF results are recorded in
[`dcg-2b-engine-b-2026-10-01`](experiments/dcg-2b-engine-b-2026-10-01.md).

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
