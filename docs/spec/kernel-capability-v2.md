# DCG kernel capability manifest and vector envelope v2

**Status: v2.0-frozen for the byte layouts and structural validation rules below.**
`DCKC` is manifest format 1 and `DCTV` is test-vector envelope format 1. This
spec freezes the shared integration input consumed by stages 2, 3, and 4. It
does not define kernel equations, prove that a callback is implemented, or
claim host/SBF parity. The example vectors are codec and normative-equation
fixtures; only execution of the registered handler can establish handler
behavior.

A change to either wire format, a field meaning, a limit, a refusal condition,
or the shared golden envelope requires all three packages to update together:
stage 2 (capabilities and kernels), stage 3 (compiler and lifecycle), and stage
4 (Python tracer and codec). Publish the replacement version and shared golden
corpus before any package consumes it. Do not reinterpret `DCKC` or `DCTV`
format version 1 in place.

## 1. Primitive rules and versioning

- Integers are unsigned little-endian `u8`, `u16`, `u32`, or `u64`; signed
  kernel values use the encoding named by their port layout. There is no
  implicit alignment or padding.
- Fixed byte strings have exactly their declared width. A length-prefixed byte
  string is `length:u32 || bytes[length]`. A record is
  `record_length:u32 || record_body[record_length]`; the length counts only
  body bytes and the body must be consumed exactly.
- Boolean and presence fields are exactly `0` or `1`. Absent optional records
  have all-zero fields and empty payloads. Unknown versions, nonzero flags or
  reserved values, duplicate or unsorted keys, invalid references, malformed
  presence fields, overflow, truncation, and trailing bytes are refused.
- Encoders reject values that do not fit before writing. Decoders use checked
  counts, lengths, products, offsets, and total sizes. They must not allocate
  based only on an untrusted declared length.
- Format version changes are required for field/order/meaning changes. A kernel
  semantic-version change changes its promised computation; an ABI-version
  change changes its canonical inputs, outputs, state, or refusal contract.
  A new image/implementation identity is required when the linked
  implementation changes. Old manifests remain valid only for the exact old
  image/profile that admitted them.
- Limits below are **designed profile limits**, not measured SVM capacity.

## 2. `DCKC` kernel capability manifest

### 2.1 Envelope

The fixed header is 16 bytes:

| Offset | Field | Width / value |
|---:|---|---|
| 0 | magic | `[4] = "DCKC"` |
| 4 | format version | `u16 = 1` |
| 6 | flags | `u16 = 0` |
| 8 | body length | `u32`, bytes after this header |
| 12 | kernel count | `u32`, in `1..=4,096` |

Kernel records follow in strictly increasing order by
`(kernel_id:[16], semantic_version:u16, abi_version:u16)`. The complete
manifest is at most 4 MiB. The body length must equal `total_length - 16`.

### 2.2 Kernel record

All records are exact-length and fields occur in this order:

1. **Identity:** `kernel_id:[16], semantic_version:u16, abi_version:u16,
   implementation_id:[32]`. Semantic and ABI versions are nonzero. IDs are
   values, not paths, names, or display strings.
2. **Parameters:** `parameter_layout_id:u32,
   parameter_layout_version:u16, max_parameter_bytes:u32`. A zero maximum
   requires zero layout ID/version; a nonzero maximum requires both IDs to be
   nonzero. The maximum is at most 65,536 bytes.
3. **Ports:** `input_port_count:u16, output_port_count:u16`, followed by all
   input ports and then all output ports. Each port is
   `port_id:u16, layout_id:u32, layout_version:u16, scalar_type:u8,
   rank:u8, byte_order:u8, alignment:u16, mutability:u8, alias_rule:u8,
   max_byte_length:u32, dimensions[rank]:u32[]`.
   Port IDs strictly increase within each direction. Rank is at most 8;
   dimensions are positive; the checked shape product times scalar width must
   fit `u32` and be no greater than `max_byte_length`. `max_byte_length` is at
   most 1 MiB. Scalar codes are `1=i8, 2=u8, 3=i16, 4=u16, 5=i32, 6=u32,
   7=i64, 8=u64, 9=opaque bytes`. Integer `byte_order` is `1` (little-endian);
   opaque bytes use `0`. Input mutability is `0` (read-only), output
   mutability is `1` (kernel-written). Alias value `0` forbids aliasing. Value
   `1` permits exact byte-range sharing among read-only input ports and is
   refused on outputs. Value `2` means exact in-place alias in the existing
   draft but is **OPEN and refused** here because the record has no field
   naming the paired input/output ports. Unknown values are refused.
4. **State:** `state_present:u8, state_schema_id:u32,
   state_schema_version:u16, max_state_bytes:u32, cursor_schema_id:u32,
   cursor_schema_version:u16, initial_state_length:u32,
   initial_state_bytes[initial_state_length],
   complete_state_commitment:u8, state_component_count:u16`, then components
   sorted by `component_id:u16`. A component is
   `component_id:u16, layout_id:u32, layout_version:u16,
   max_read_bytes:u32, max_write_bytes:u32, initial_bytes_length:u32,
   initial_bytes[initial_bytes_length]`.
   When `state_present=0`, all state fields, counts and payloads are zero or
   empty. When present, schema ID/version and maximum are nonzero, initial
   state fits the maximum, and cursor schema is either `(0,0)` or a nonzero
   `(id,version)` pair. Each component layout ID/version is nonzero and its
   initial bytes fit `max_write_bytes`. `complete_state_commitment` is a
   Boolean: `1` promises the commitment covers the complete canonical state
   bytes defined by the registered state schema; `0` makes no such promise. A
   backend requiring a full before/after state commitment refuses a stateful
   kernel that does not advertise that capability.
5. **Step ABI:** `step_abi_id:u32, step_abi_version:u16,
   decomposition_id:u32, decomposition_version:u16, max_step_count:u32,
   whole_sweep_supported:u8`. ABI and decomposition IDs/versions are
   nonzero; `max_step_count` is in `1..=16,384`; the last field is a Boolean.
   The decomposition is finite and indexed. `whole_sweep_supported` does not
   imply that a particular plan fits one instruction; plan admission checks
   actual image limits.
6. **Mode declarations:** `mode_count:u16`, then records sorted by
   `(mode_id:u32, version:u16)`. Each is
   `mode_id:u32, version:u16, required_capability_count:u16`, required
   capabilities sorted by `(capability_id:[16], version:u16)` and encoded as
   `capability_id:[16], version:u16`, `scheme_count:u16`, schemes sorted by
   `(scheme_id:u32, version:u16)` and encoded as `scheme_id:u32, version:u16`,
   `replay_present:u8`, then fixed replay fields:
   `replay_abi_id:u32, replay_abi_version:u16, max_input_spans:u16,
   max_prior_state_bytes:u32, max_output_bytes:u32, max_next_state_bytes:u32,
   max_authentication_path_nodes:u16, max_opening_bytes:u32,
   allowed_account_roles:u32, max_svm_cu:u64`.
   Mode and capability membership is exact: a plan may use only a declared
   mode and required capability set. If replay is absent, every replay field
   is zero. If present, replay ABI ID/version and opening maximum are
   nonzero; the opening maximum is at most 4 KiB. Scheme and capability
   versions are nonzero. An image/compiler refuses an unregistered mode,
   capability, scheme, layout, replay ABI, or account-role bit.
7. **Resource ceilings:** `max_input_bytes:u32, max_output_bytes:u32,
   max_operations:u32, max_accounts:u16, max_cu:u64, max_heap_bytes:u32,
   max_stack_bytes:u32, max_concurrent_live_states:u32,
   max_live_state_bytes:u32`. Each field is a maximum, not an estimate;
   zero means no capacity is declared for that resource.
8. **Stable refusal mapping:** `error_mapping_count:u16`, then records sorted by
   `condition_id:u16`, each `condition_id:u16, stable_error_code:u16`. Both
   values are nonzero and condition IDs are unique. Every malformed input,
   overflow, invalid length, forbidden alias, or domain refusal possible under
   the kernel ABI must map to a stable error code.

### 2.3 Hash and compatibility

The manifest root is the flat, domain-separated SHA-256 digest

`SHA256(ASCII("dcg.kernel.manifest.id.v2") || 0x00 || canonical_DCKC_bytes)`.

It is not a Merkle tree. Plans bind this exact 32-byte root and separately bind
the application image identity. Display hex is never hashed. Python and Rust
encoders must reproduce the same canonical manifest bytes and root.

The profile-1 kernel registry is `add_i32/1` and `identity_i32/1` for the
minimal first slice. Their scalar ABI is signed two's-complement `i32` encoded
as four little-endian bytes. `add_i32/1` adds its two inputs with checked
signed-32-bit overflow refusal; `identity_i32/1` copies its one input exactly.
The error-condition and stable-code assignment for overflow remain OPEN until
the kernel error registry is agreed. Graph/plan profile 1 admits
`optimistic/1`,
`consensus/1`, `sha256-merkle/1`, and the version-1 layouts listed in
[`graph-plan-v2.md`](graph-plan-v2.md). A capability declaration does not
itself prove that its callback is present: image validation checks the exact
kernel ID, semantic version, ABI version, implementation identity, declared
mode membership, and callback presence before plan admission.

## 3. `DCTV` deterministic test-vector envelope

`DCTV` is a versioned offline artifact for carrying captured, normative, or
derived vectors. It is not a chain account or a proof. A valid DCTV record must
be checked against its manifest and kernel ABI by the host vector runner; a
successful envelope decode proves only canonical structure.

### 3.1 Envelope

The fixed header is 16 bytes:

| Offset | Field | Width / value |
|---:|---|---|
| 0 | magic | `[4] = "DCTV"` |
| 4 | format version | `u16 = 1` |
| 6 | flags | `u16 = 0` |
| 8 | body length | `u32`, bytes after this header |
| 12 | vector count | `u32`, nonzero |

The body is exactly `vector_count` length-prefixed records. The body length
and every record length fit `u32`; complete size is at most `16 + (2^32 - 1)`
bytes. Tools must impose a smaller local processing cap before loading large
files. Records are sorted by `vector_id:[16]`, strictly increasing.

### 3.2 Vector record

Fields occur in this order inside each exact-length record:

1. `vector_id:[16], kernel_id:[16], semantic_version:u16, abi_version:u16,
   manifest_root:[32]`.
2. `source_kind:u8, source_identity:[32], generator_id:[16],
   generator_version:u16, seed:[32]`.
   `source_kind=0` is a captured run/trace; `1` is a normative kernel
   equation; `2` is a mechanically derived mutation. For kinds 0 and 1,
   generator ID/version and seed are all zero. For kind 2, generator ID and
   version are nonzero, seed is exactly 32 bytes, and `source_identity`
   identifies the parent capture/vector. The normative-equation fixture
   identity used by the initial corpus is
   `SHA256("dcg.kernel.vector.equation.v1\0" || kernel_id ||
   semantic_version:u16le || abi_version:u16le)`.
3. `parameter_length:u32, parameter_bytes[]`.
4. `input_count:u16`, followed by `input_count` values sorted by `port_id:u16`;
   each value is `port_id:u16, value_length:u32, value_bytes[]`.
5. `prior_state_length:u32, prior_state_bytes[]`.
6. `expected_outcome:u8`. For `0` (output), encode
   `output_count:u16`, output values sorted by the same `port_id` rule and
   interpreted using the manifest's output-port layouts, then
   `next_state_length:u32, next_state_bytes[]`.
   For `1` (refusal), encode `stable_error_code:u16`; no output or next-state
   fields follow. Other values are refused.

Port-value IDs are unique and strictly increasing. The root and kernel
identity must match the manifest record used by the runner; parameter, input,
state, output and error bytes must match the referenced ABI. The vector codec
checks widths, ordering, exact record consumption and outcome structure; it
does not evaluate the kernel or resolve registry IDs.

For a derived vector, the generator selects a captured input and applies
recorded deterministic mutations for length, range, alignment, overflow, or
malformed-byte boundaries. Store the original source identity, generator ID
and version, seed, exact bytes, expected canonical result or refusal code.
Expected outputs must come from the normative kernel equation or a captured
run/chain receipt; never derive expected output solely by calling the
implementation under test. Feed the same DCTV bytes to host and SBF handler
tests. A Python test of these bytes is codec coverage, not handler evidence.

## 4. Refusals and stable diagnostics

Both decoders refuse unknown versions; nonzero flags/reserved fields;
truncation; body-length mismatch; unconsumed record bytes; trailing bytes;
invalid counts; checked-length or shape overflow; invalid presence/outcome
values; noncanonical ordering; duplicate IDs; unsupported format registries;
invalid port layouts; invalid state or replay declarations; and nonzero
DCKC alias rule `2` while its pair ABI is OPEN. They refuse before accepting
the record as canonical. No prefix parsing or ignored extension fields are
permitted.

The Python reference exposes stable diagnostic strings for its tests. DCTV
uses `MAGIC`, `VERSION`, `FLAGS`, `BODY_LENGTH`, `VECTOR_COUNT`, `ORDER`,
`DUPLICATE`, `INTEGER_RANGE`, `FIXED_WIDTH`, `TRUNCATED`, `TRAILING_BYTES`,
`SOURCE_KIND`, `SOURCE_METADATA`, `OUTCOME`, `OUTCOME_FIELDS`, and
`ERROR_CODE`. DCKC uses the corresponding `GraphError.code` values, including
`KERNEL_COUNT`, `ORDER`, `DUPLICATE`, `VERSION`, `PRESENCE`, `PRESENCE_FIELDS`,
`PORT_LAYOUT`, `BYTE_ORDER`, `MUTABILITY`, `ALIAS_RULE_OPEN`, `STATE_FIELDS`,
`STEP_ABI`, `REPLAY_ABI`, `OPENING_LIMIT`, and `ERROR_MAPPING`. These host
strings are not SVM error numbers. On-chain stable error numbers are the
kernel's manifest `stable_error_code` values.

## 5. Open registries and owner decisions

These items are deliberately **OPEN**; the byte layout above does not assign
application semantics or invent registry values:

- Registry allocation and semantic definitions for capability IDs, mode and
  commitment IDs beyond the admitted profile-1 values, port/state/cursor
  layouts, decomposition IDs, admission rules, replay ABIs, and account-role
  mask bits.
- The shared stable `condition_id` and `stable_error_code` registry, including
  the condition names used by the first SVM handlers. Values in the current
  minimal DCKC fixture are codec-conformance values only, not approved global
  error assignments.
- The pairing ABI needed to enable alias rule `2`; until a versioned record
  names the in-place input/output pair, DCKC v1 refuses it.
- State-schema-specific interpretation of component IDs, initial-state
  encoding, cursor bytes, and the exact commitment root for componentized
  state. A backend may use stateful capabilities only after that schema is
  registered and the selected mode's complete-state requirement is met.
- The reproducible build procedure that derives `implementation_id` and
  `app_image_id`, and the policy mapping an image identity to a deployed
  program address.
- The normalization/identity procedure for captured run and trace artifacts,
  the registered mutation-generator IDs and algorithms, and any cross-run
  seed derivation. DCTV stores these identities but does not authenticate
  provenance.
- A smaller operational DCTV file/queue limit. The wire representation is
  bounded by its `u32` lengths; each runner must choose a smaller local cap
  before processing it.

The v2.0 first slice avoids relying on these open details where possible: its
two kernels are stateless, use the frozen signed-`i32` port layout, and use the
single optimistic/SHA-256-Merkle profile. Resolving an OPEN item that changes
bytes, field meaning, refusal behavior, or admissible execution requires a
new shared contract update across stages 2, 3, and 4.

## 6. Python reference and golden corpus

The pure-Python reference manifest encoder/root is
`python/dcg/graph/v2.py` (`encode_kernel_manifest`,
`decode_kernel_manifest`, `kernel_manifest_root`). The DCTV reference codec is
`python/dcg/graph/kernel_capability_v2.py`. Both use only the Python standard
library and validate canonical bytes without RPC, Rust, SBF, or chain access.

The small golden corpus is `tests/golden/dcg/kernel_capability_v2/`; the
reproducer is `scripts/dcg_kernel_capability_v2_goldens.py`. It reuses the
minimal `add_i32/1` and `identity_i32/1` capability declarations from the
frozen graph-plan example and records one normative output vector for each.
Those vectors verify encoding of a checked `2 + 3 = 5` and `identity(5) = 5`;
they are not a kernel-handler test or a performance measurement.

Run offline from the repository root:

```sh
cd python
PYTHONPATH=. python ../scripts/dcg_kernel_capability_v2_goldens.py
PYTHONPATH=. pytest -q tests/test_kernel_capability_v2.py
PYTHONPATH=. pytest -q tests/test_graph_plan_v2.py
```
