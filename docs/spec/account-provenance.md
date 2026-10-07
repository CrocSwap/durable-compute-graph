# Program account address provenance

Status: implementation rule for DCG program-owned account reads and writes.
The revision-8 lifecycle, and with it the gaps this page listed for its records,
was retired after v0.1.0-alpha (that tag keeps the earlier text).

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
magic, data-length bounds, and optional version. `expect_derived_with_bump`
uses one address derivation with a bump stored by an existing creator that used
the canonical search; it returns a `StoredBump`, checks a configured bump field,
and does not search again. `expect_system_derived_with_bump` returns the same
read-only token after checking a stored bump against an empty System-owned
target. A read role accepts a writable meta when the frozen account list already
grants it; a writer must receive a writable meta. `expect_keyed` applies the
same shape and privilege checks when the identity is an independently
authenticated non-PDA key, such as the key of a fresh account whose signature
authorizes its initialization. Before creation, `expect_system_derived` checks
a fresh system-owned PDA. The shared creation functions take a canonical bump
obtained by the caller and verify it with one address derivation before
creating or assigning the account; `allocate_derived_account` keeps the
format's existing pre-funding behavior.

Every program-owned PDA creation must use `CanonicalBump`: the opaque type
pairs the address with the bump returned by a full canonical search. Creation
helpers accept that type instead of an arbitrary byte, use its paired address,
and sign with its bump without deriving the address a second time. A
`StoredBump` cannot be passed to creation helpers. A stored bump is trusted
only because DCG created the record through the full-search path; readers then
verify the address with one fixed-cost derivation.

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

Known gaps in the compatibility stateful adapters:

- **Stateful v1/v2 sessions and some v3 operations.** The current adapters
  validate the session PDA canonically and require an independent authority
  signer when the instruction includes that authority. Other instructions do
  not include that signer; they retain self-seeded session validation. Child
  stream, state, resource, and view accounts are checked against keys stored
  in the validated session; anchors derive from the validated session key.
- **Retired-image tags 7, 100, 111, and 112.** Those routes are not dispatched
  by this source revision. This change does not patch or qualify a deployed
  older image; the tag-7 writer and the zeroed-account takeover paths need the
  matching image-level repair before that image can claim this rule.

These gaps do not authorize reading or mutating an account of another kind.
The existing owner, kind, size, lifecycle, and role checks remain in force;
the gap is specifically that some identity sources are the target's own bytes.

## Caller-validated readers and current shared-gate coverage

The shared gate is used by the stateful session/stream/state/resource/view/
anchor checks and creators. Existing direct checks remain where they also enforce
lifecycle-specific rules.

Stateful sessions v3 (review 10-05): every child creator (stream, state,
views, scratch, workspace) requires the session authority's signature at
account 2, and creation adopts pre-funded empty system addresses. Lane records
are self-seeded: `checked_lane` derives the record's address from the session
key stored in the record itself, which is sound because only the program can
create an account at that derived address (lane creation requires the
authority).

The source audit `account_provenance_lint.rs` discovers Rust files under
`src/` and checks direct account-write calls in functions, trait defaults, and
`impl` methods of every visibility. It compares findings with a reviewed
allowlist, so a new unguarded writer fails the test until reviewed. Macro bodies
are scanned for writer and gate identifiers where feasible. This audit does
not track data flow, account-to-gate correspondence, or whether a gate runs
before the write. Code review must trace each seed and each write back to its
validated source.
