# Program account address provenance

Status: implementation rule for DCG program-owned account reads and writes.
Revision-8 DCR1 uses reserved bytes for the challenge bump, marker, and response
PDA bump.

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
the canonical search; it checks a configured bump field but does not search
again. A read role accepts a writable meta when the frozen account list already
grants it; a writer must receive a writable meta. `expect_keyed` applies the
same shape and privilege checks when the identity is an independently
authenticated non-PDA key, such as the key of a fresh account whose signature
authorizes its initialization. Before creation, `expect_system_derived` checks
a fresh system-owned PDA. The shared creation functions take a canonical bump
obtained by the caller and verify it with one address derivation before
creating or assigning the account; `allocate_derived_account` keeps the
format's existing pre-funding behavior.

Every program-owned PDA creation must use `CanonicalBump`: the opaque type
pairs the address with the bump returned by a full canonical search, or by a
stored bump that has passed the account's expected-address and kind checks.
Creation helpers accept that type instead of an arbitrary byte, use its paired
address, and sign with its bump without deriving the address a second time.
This makes the canonical-bump invariant explicit at the creation boundary. A
stored bump is trusted only because DCG created the record through the
full-search path; readers then verify the address with one fixed-cost
derivation.

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

- **DCR1 challenge records and closure-v2 response tags 115–118/125.** Open
  validates the new address from the instruction descriptor, challenger
  signer, and nonce, then stores the canonical challenge bump at byte 146,
  marker `1` at byte 147, and the canonical DRU1 response bump staged at byte
  181, then moved to byte 219 after tag 164 consumes position roots.
  Challenge readers require marker `1`; this image is intended for a fresh
  program address, so pre-image marker-0 DCR1 records are refused. Revision-8
  tag 131 uses the stored DCR1 and DRU1 bumps for fixed-cost address checks;
  tag 132's timeout RULE uses the stored DCR1 bump. Tag 132 has no DRU1 account
  in its list. Revision-7 settlement retains the canonical DRU1 search because
  its records predate these bump fields. The account lists provide no independent challenge identity
  anchor, so the seed source remains self-seeded.
- **DCM2 identity for tag 172.** Its account list contains no independent
  document identity anchor. The close path currently derives the document
  identity from DCM2/DCR2 data or instruction data. A future account list must
  provide a validated parent identity before this path can meet the rule for
  every record.
- **DCR2 identity for tag 185.** The close-result account list has no validated
  parent record; it takes the descriptor from instruction data and derives the
  result PDA from it. The shared gate still checks the result PDA's canonical
  address, owner, shape, and role, but the descriptor remains an unchecked
  identity input. A future account list must anchor it independently.
- **DCRZ tombstone identity for tag 187.** Settlement reads the descriptor
  from the tombstone and the shared gate checks the DCRZ address, kind, version,
  and shape from that descriptor. Tag 187 has no parent document account, so
  this reader remains self-seeded.
- **Stateful v1/v2 sessions and some v3 operations.** The current adapters
  validate the session PDA canonically and require an independent authority
  signer when the instruction includes that authority. Other instructions do
  not include that signer; they retain self-seeded session validation. Child
  stream, state, resource, and view accounts are checked against keys stored
  in the validated session; anchors derive from the validated session key.
- **PT1X/PT2S state.** Initialization is authenticated by the account signers.
  Later PT1X uploads/seals and PT2S hash operations omit an independent state
  identity anchor; their current state checks validate kind and shape, not
  provenance from another account. A later wire version must bind the state
  key through an independently validated parent or signer role on every write.
- **Generic PT1/PT2P `owned()` helpers and plan readers.** The helpers only
  check program ownership because they have no parent identity argument. The
  plan reader checks routes, geometry, payload, and PT1S against keys stored in
  PT2S. Its callers must first validate that PT2S key against the document or
  admission record; the helper itself cannot prove that relationship.
- **Retired-image tags 7, 100, 111, and 112.** Those routes are not dispatched
  by this source revision. This change does not patch or qualify a deployed
  older image; the tag-7 writer and the zeroed-account takeover paths need the
  matching image-level repair before that image can claim this rule.

These gaps do not authorize reading or mutating an account of another kind.
The existing owner, kind, size, lifecycle, and role checks remain in force;
the gap is specifically that some identity sources are the target's own bytes.

## Caller-validated readers and current shared-gate coverage

Several readers use identity fields internally but rely on their handler
caller to supply a separately checked parent identity. `admission::view` and
`registry::view` validate their PDA and shape from their own header fields;
document initialization independently compares admission identity against the
validated registry/PT2S path, and config callers independently authenticate
the registry. `result::close_v7` validates DCM2 before checking DFS2 against
the document descriptor. Template seal/use records are gated from the PT2S
key and digest. These caller relationships must remain in place when call sites
change.

The shared gate is used by the revision-8 DCM2/DPR2/DCR2 readers, DCR1 readers
and open creator, DRU1 readers and creator, unified PDA creation,
descriptor-bound bond escrow validation, stateful session/stream/state/resource/
view/anchor checks and creators, PT1X signer initialization and PT1O output
PDAs, PT2S signer initialization, and the selected template, admission,
registry, and plan readers. Existing direct checks remain where they also
enforce lifecycle-specific rules.

The source audit `account_provenance_lint.rs` discovers Rust files under
`src/` and checks direct account-write calls in functions, trait defaults, and
`impl` methods of every visibility. It compares findings with a reviewed
allowlist, so a new unguarded writer fails the test until reviewed. Macro bodies
are scanned for writer and gate identifiers where feasible. This audit does
not track data flow, account-to-gate correspondence, or whether a gate runs
before the write. Code review must trace each seed and each write back to its
validated source.
