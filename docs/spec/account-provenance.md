# Program account address provenance

Status: implementation rule for DCG program-owned account reads and writes.
This rule does not change any account bytes or instruction layout.

## Rule

Before a handler reads or writes a program-owned account, it must validate the
account's exact address from identity inputs that are independent of the target
account. Valid seed sources are:

- a parent record whose address and kind have already passed this gate;
- the key of a required transaction signer;
- a fixed program constant or a fixed program id; or
- an instruction identity that has been checked against one of those sources.

The account's own bytes and an unchecked instruction field cannot establish its
expected address. A PDA check made from the target's own descriptor, authority,
nonce, bump, or child key is self-seeded and does not satisfy this rule.

The shared `account_provenance::expect_derived` gate checks the canonical PDA,
program owner, non-executable status, required writable/signer privileges,
magic, data-length bounds, optional version, and optional stored canonical
bump. A read role accepts a writable meta when the frozen account list already
grants it; a writer must receive a writable meta. `expect_keyed` applies the same shape and privilege checks when the
identity is an independently authenticated non-PDA key, such as the key of a
fresh account whose signature authorizes its initialization. Before creation,
`expect_system_derived` checks a fresh system-owned PDA. The shared
`create_derived_account` and `allocate_derived_account` functions validate the
canonical address and bump before creating or assigning it; the latter keeps
the format's existing pre-funding behavior.

Callers must validate the seed sources before invoking these helpers. The
helpers cannot infer whether arbitrary bytes passed as `seeds` came from a
validated parent; the caller's gate is part of the security argument.

## Exceptions and known gaps

There is no account-role exception that makes a self-seeded address valid. A
non-program-owned signer, recipient, System Program account, or other runtime
program account is checked by its exact signer key or fixed id and is not a
program-owned record. When an existing instruction has no independent identity
source for a program-owned record, its wire format is preserved and the gap is
listed below for the next program version. Such a path must not be described as
meeting the independent-source rule.

Known gaps in the `revision-8` account lists and the compatibility stateful
adapters:

- **DCR1 challenge records.** Open validates the new address from the
  instruction descriptor, challenger signer, and nonce. Later challenge and
  replay handlers receive no independent challenge-identity anchor; the
  revision-8 record only carries its descriptor, challenger, and nonce. The
  shared reader therefore rechecks canonical address, owner, kind, size, and
  privileges from those record fields, but that read is self-seeded.
- **DCM2 identity for tag 172.** Its account list contains no independent
  document identity anchor. The close path currently derives the document
  identity from the DCM2/DCR2 data or instruction descriptor. A future account
  list must provide a validated parent identity before this path can meet the
  rule for every record.
- **DCR2 identity for tag 185.** The close-result account list has no validated
  parent record; it takes the descriptor from instruction data and derives the
  result PDA from it. The shared gate still checks the result PDA's canonical
  address, owner, shape, and role, but the descriptor remains an unchecked
  identity input. A future account list must anchor it independently.
- **Stateful v1/v2 sessions and some v3 operations.** The current adapters
  validate the session PDA canonically and require an independent authority
  signer when the instruction includes that authority. Other instructions do
  not include that signer; they retain self-seeded session validation. Child
  stream, state, resource, and anchor accounts are checked from the validated
  session key.
- **PT1X/PT2S state.** Initialization is authenticated by the account
  signers. Later PT1X uploads/seals and PT2S hash operations omit an independent
  state identity anchor; their current state checks validate kind and shape,
  not provenance from another account. A later wire version must bind the state
  key through an independently validated parent or signer role on every write.
- **Retired-image tags 7, 100, 111, and 112.** Those routes are not dispatched
  by this source revision. This change does not patch or qualify a deployed
  older image; the tag-7 writer and the zeroed-account takeover paths need the
  matching image-level repair before that image can claim this rule.

These gaps do not authorize reading or mutating an account of another kind.
The existing owner, kind, size, lifecycle, and role checks remain in force;
the gap is specifically that some identity sources are the target's own bytes.

## Current shared-gate coverage

The helper is wired into the shared revision-8 DCM2/DPR2/DCR2 readers, the
DCR1 reader and open creator, DRU1 reads and creator, unified PDA creation,
descriptor-bound bond escrow validation, stateful session/stream/state/resource/
anchor checks and creators, PT1X signer initialization and PT1O output PDAs,
and PT2S signer initialization. Existing direct checks remain where they also
enforce lifecycle-specific rules. New handlers must either call the shared
gate directly or route through one of these validated account boundaries.

The source-contract test `account_provenance_lint.rs` pins those shared-gate
boundaries so a refactor cannot silently remove the common checks. The test is
a source guard, not a proof that the helper's seed arguments have trustworthy
origins; code review must trace each seed back to its validated source.
