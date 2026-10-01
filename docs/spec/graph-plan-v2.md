# DCG graph and plan v2 wire profile

**Status: proposed frozen bytes for review.** This document turns the shared
DCG v2 interface draft dated 2026-10-01 into canonical bytes. The numeric
limits below are designed admission ceilings, not measured chain capacity.
The Python implementation is a reference for consensus bytes and structural
refusals; it does not implement kernels, compiler lowering, or SVM handlers.

The owner answers in the shared draft apply: there are no graph loops; each
region has one mode; the first slice uses SHA-256 Merkle commitments; graph and
plan bytes are stored once on chain in fixed-index shards; and each plan binds
the compiler, application image, and kernel-manifest identities. The owner
changed D8 to a shared pre-deployed testnet program with a general kernel
library. Apps with custom kernels still use their own static image. The first
slice therefore requires no program deployment, and its template still binds
the exact image identity.

## 1. Primitive encoding rules

- Integers are unsigned little-endian `u8`, `u16`, `u32`, or `u64` unless a
  field says otherwise. There is no implicit alignment or padding.
- Fixed byte strings have exactly their declared width. Variable byte strings
  have a `u32` byte length followed by exactly that many bytes, except where a
  record table spells out the length and payload as separate fields.
- Every record is `record_length:u32 || record_body[]`. `record_length` counts
  only the body bytes. The body must consume the record exactly; trailing bytes
  are refused. Sections have only the counts in their envelope; there are no
  separators between records.
- For `DCGG`, `body_length` is the number of bytes after the 32-byte fixed
  header. For `DCPL`, it is the number of bytes after the 162-byte fixed
  header, including compiler parameters and all records. For `DCKC`, it is the
  number of bytes after the 16-byte fixed header.
- Encoders reject integers outside their field width before writing. Decoders
  use checked lengths, products, offsets, and counts. No integer wrapping is
  permitted.
- Unknown versions, nonzero flags/reserved fields, duplicate keys, unsorted
  records, malformed presence fields, invalid references, unsupported
  registries, bytes after the final section, and input above the profile size
  ceiling are refused. Text, floating point, host paths, pointers, timestamps,
  and display encodings are not wire values.
- A scalar has rank zero and shape product one. Shape dimensions must be
  positive. Scalar codes are `1=i8, 2=u8, 3=i16, 4=u16, 5=i32, 6=u32,
  7=i64, 8=u64, 9=opaque bytes`; widths are respectively `1,1,2,2,4,4,8,8,1`.
  Opaque bytes have no integer interpretation.
- Port alignment is a nonzero power of two that fits `u16`. `byte_length` is
  the checked shape product times scalar width. `max_byte_length` must be at
  least `byte_length`. Both are at most 1 MiB.
- Directions are input `0` and output `1`. A port key is
  `(node_id, direction, port_id)`. A step port reference is exactly
  `(node_id:u32, direction:u8, port_id:u16)`.
- Profile 1 accepts only `consensus/1` (`mode_id=0x434f4e53`),
  `optimistic/1` (`0x4f505449`), `sha256-merkle/1`
  (`scheme_id=2`), and the version-1 layouts `full-trace/1` (`layout_id=1`)
  and `checkpointed-state-layout/1` (`layout_id=2`). Unknown future registry
  values are refused by this profile. IDs are encoded little-endian.
- Region ID zero is the sole root. `0xffffffff` is reserved as its parent
  sentinel and cannot be used as a region ID. Depth counts the root.

The Python module raises `GraphError` or `PlanError`, each with a stable
`.code`. Code names are part of this reference implementation's diagnostic
interface; the wire contract is the refusal condition, not Python exception
text.

## 2. DCGG graph bytes

### 2.1 Envelope

| Offset | Field | Width / value |
|---:|---|---|
| 0 | magic | `[4] = "DCGG"` |
| 4 | format version | `u16 = 1` |
| 6 | flags | `u16 = 0` |
| 8 | body length | `u32`, bytes after this 32-byte header |
| 12 | node count | `u32` |
| 16 | port count | `u32` |
| 20 | edge count | `u32` |
| 24 | region count | `u16` |
| 26 | graph input count | `u16` |
| 28 | graph output count | `u16` |
| 30 | reserved | `u16 = 0` |

The fixed header is 32 bytes (the table's last row ends at offset 32); the body
starts at offset 32. The `body_length` value is `total_length - 32`. Sections
follow in this exact order: nodes, ports, edges, regions, graph inputs, graph
outputs. Counts are records, not bytes. At least one node and region are
required. There is exactly one root region and every declared region must
contain a node or a nonempty descendant region.

### 2.2 Record bodies

Every field below occurs in table order inside its record body.

| Record | Fields |
|---|---|
| Node | `node_id:u32, kernel_id:[16], semantic_version:u16, abi_version:u16, region_id:u32, state_present:u8, state_schema_id:u32, state_schema_version:u16, max_state_bytes:u32, parameter_layout_id:u32, parameter_layout_version:u16, parameter_length:u32, parameter_bytes[]` |
| Port | `node_id:u32, direction:u8, port_id:u16, layout_id:u32, layout_version:u16, scalar_type:u8, rank:u8, alignment:u16, reserved:u16=0, byte_length:u32, max_byte_length:u32, dimensions[rank]:u32[]` |
| Edge | `source_node:u32, source_port:u16, destination_node:u32, destination_port:u16` |
| Region | `region_id:u32, parent_region_id:u32, mode_id:u32, mode_version:u16, scheme_id:u32, scheme_version:u16, layout_id:u32, layout_version:u16, mode_parameter_length:u32, mode_parameters[], scheme_parameter_length:u32, scheme_parameters[], layout_parameter_length:u32, layout_parameters[]` |
| Graph input | `external_id:u32, destination_node:u32, destination_port:u16, reserved:u16=0` |
| Graph output | `external_id:u32, source_node:u32, source_port:u16, reserved:u16=0` |

`state_present` is `0` or `1`. When it is zero, all three state fields are
zero. When it is one, schema ID/version and `max_state_bytes` are nonzero.
State bytes are values supplied at run time; the node record commits the
schema and maximum, not the initial run state.

An empty node parameter block has zero layout ID/version and length. A
nonempty block requires nonzero layout ID/version and is at most 64 KiB. Its
contents are canonical bytes of the referenced kernel parameter ABI; the
graph codec treats them as opaque.

Records are sorted by these keys, strictly increasing:

- Node: `node_id`.
- Port: `(node_id, direction, port_id)`.
- Edge: `(destination_node, destination_port, source_node, source_port)`.
- Region: `region_id`.
- Input and output: `external_id`, independently for each section.

An edge connects an existing output to an existing input. Their layout ID and
version, scalar type, dimensions, byte length, and alignment must all match.
Each input port has exactly one source, either one edge or one graph-input
record. Each output port is used by at least one edge or named by a graph
output. Output fan-out is allowed; duplicate edges are not. Graph node edges
must form a DAG. A cycle, including a self-edge, is refused.

Every node names an existing region. Parent links must resolve and reach region
zero without a cycle. The graph may have direct nodes in a parent region as
well as nodes in child regions. This interprets “owning region” as the node's
single declared region; it allows the first-slice parent identity kernel and
child add kernel in one region tree.

## 3. DCPL plan bytes

### 3.1 Envelope and sections

| Field | Width / value |
|---|---|
| magic | `[4] = "DCPL"` |
| format version | `u16 = 1` |
| flags | `u16 = 0` |
| body length | `u32`, bytes after the 162-byte fixed header |
| graph ID | `[32]` |
| compiler ID | `[16]` |
| compiler semantic, front-end/IR, lowering versions | three `u16` values |
| admission-ruleset ID/version | `u32, u16` |
| application-image ID | `[32]` |
| kernel-manifest root | `[32]` |
| region count | `u16` |
| step, segment, boundary, translation, cost counts | five `u32` values |
| compiler-parameter length | `u32` |
| compiler parameters | that many bytes |

The fixed portion is 162 bytes; compiler parameters follow it, then records in
this exact order: region plans, steps, segments, boundaries, translations, cost
admissions. `body_length` includes compiler parameters and records. Plan bytes
include the graph ID, compiler and parameters, application image, manifest
root, selected mode/commitment settings, lowering order, and admitted ceilings.
Diagnostic estimates do not enter these bytes.

Records use the common `u32 length || exact body` form.

| Record | Fields |
|---|---|
| Region plan | `region_id:u32, parent_region_id:u32, mode_id:u32, mode_version:u16, scheme_id:u32, scheme_version:u16, layout_id:u32, layout_version:u16, direct_step_count:u32, segment_count:u32, mode_params_len:u32, mode_params[], scheme_params_len:u32, scheme_params[], layout_params_len:u32, layout_params[]` |
| Step | `ordinal:u64, region_id:u32, segment_id:u32, node_id:u32, kernel_step:u32, decomposition_id:u32, decomposition_version:u16, input_count:u16, input_port_refs[], output_count:u16, output_port_refs[]` |
| Segment | `region_id:u32, segment_id:u32, first_step:u64, step_count:u32, root_scheme_id:u32, root_scheme_version:u16` |
| Boundary | `source_region:u32, destination_region:u32, source_port_ref, destination_port_ref, layout_id:u32, layout_version:u16, scheme_id:u32, scheme_version:u16, cursor_schema_id:u32, cursor_schema_version:u16` |
| Translation | `source_scheme_id:u32, source_version:u16, target_scheme_id:u32, target_version:u16, relation_or_kernel_id:[16], semantic_version:u16, abi_version:u16, input_layout_id:u32, input_layout_version:u16, output_layout_id:u32, output_layout_version:u16, max_input_bytes:u32, max_output_bytes:u32, max_cu:u64, max_accounts:u16, max_opening_bytes:u32` |
| Cost admission | `scope_kind:u8, region_id:u32, step_ordinal:u64, max_cu:u64, max_accounts:u16, max_read_bytes:u32, max_write_bytes:u32, max_operations:u32, max_heap_bytes:u32, max_stack_bytes:u32, max_input_bytes:u32, max_output_bytes:u32, max_state_bytes:u32, max_opening_bytes:u32` |

Input and output port-reference lists are each strictly sorted by
`(node_id, direction, port_id)`, with input direction `0` and output direction
`1`. The plan step ordinal is global and contiguous from zero. A
`(node_id,kernel_step)` pair is unique. Kernel step decomposition is finite.

Region plans are sorted by `region_id`; steps by `ordinal`; segments by
`(region_id,segment_id)`; boundaries by `(source_region,destination_region,
source_port_ref,destination_port_ref)`; translations by source/target scheme
identity then relation/kernel and input/output layout identity; costs by
`(scope_kind,region_id,step_ordinal)`. All keys are strictly increasing.

Segment IDs start at zero for each region and are contiguous. Each segment has
positive `step_count`, owns a contiguous global ordinal interval, and every
step in that interval has the segment's region and segment ID. Segment
intervals partition `[0, step_count)` exactly once. A region plan's direct
step and segment counts equal the corresponding records.

Every plan region tree is rooted at zero with parent sentinel `0xffffffff`,
has depth at most eight including the root, and uses one resolution mode, one
commitment scheme, and one layout per region. Each step and region has one cost
record plus exactly one run-scope cost record. Cost scope keys are:

- Step (`1`): known `region_id` and `step_ordinal`; the region must match that
  step.
- Region (`2`): known `region_id`; unused `step_ordinal` is zero.
- Run (`3`): both unused keys are zero.

All openings are at most 4 KiB. Translation records are present in the wire
table for compatibility with the shared IR, but profile 1 only admits the
single SHA-256 Merkle scheme and therefore has no usable cross-scheme
translation. A profile-1 plan with a translation is refused.

## 4. Kernel capability declaration (`DCKC`)

The shared draft names the `KernelCapabilityManifest/1` fields but does not
give them bytes. This section defines a proposed canonical manifest envelope
so `kernel_manifest_root` can be recomputed. It is not part of `DCGG` or
`DCPL`; a plan binds its 32-byte root. Manifest field IDs that describe an
application ABI remain registry-owned and are not guessed by the codec.

`DCKC` has magic `[4]="DCKC"`, `format_version:u16=1`, `flags:u16=0`,
`body_length:u32` (bytes following its 16-byte header), and
`kernel_count:u32`. `kernel_count` is in `1..4,096`; complete DCKC bytes are
at most 4 MiB. The body is kernel records sorted by
`(kernel_id,semantic_version,abi_version)`. A kernel record is length-prefixed
and contains, in order:

1. `kernel_id:[16], semantic_version:u16, abi_version:u16,
   implementation_id:[32]`.
2. `parameter_layout_id:u32, parameter_layout_version:u16,
   max_parameter_bytes:u32`.
3. `input_port_count:u16, output_port_count:u16`, then input ports and output
   ports. Each port has `port_id:u16, layout_id:u32, layout_version:u16,
   scalar_type:u8, rank:u8, byte_order:u8, alignment:u16,
   mutability:u8, alias_rule:u8, max_byte_length:u32, dimensions[rank]:u32[]`.
   Port IDs increase within each direction. Integer ports use byte order `1`
   (little-endian); opaque-byte ports use `0`. Mutability is read-only `0` or
   kernel-written `1`. Alias rule is `0` (no alias), `1` (read-only sharing),
   or `2` (exact in-place alias); profile 1 graph edges do not imply aliasing.
4. `state_present:u8, state_schema_id:u32, state_schema_version:u16,
   max_state_bytes:u32, cursor_schema_id:u32, cursor_schema_version:u16,
   initial_state_length:u32, initial_state_bytes[],
   complete_state_commitment:u8, state_component_count:u16`, then state
   components sorted by `component_id:u16`. A component is
   `component_id:u16, layout_id:u32, layout_version:u16, max_read_bytes:u32,
   max_write_bytes:u32, initial_bytes_length:u32, initial_bytes[]`. When
   `state_present=0`, every state field, count, and payload is zero/empty.
   When present, the state schema and maximum are nonzero, initial bytes fit
   the maximum, and `complete_state_commitment` is `0` or `1`.
5. `step_abi_id:u32, step_abi_version:u16, decomposition_id:u32,
   decomposition_version:u16, max_step_count:u32, whole_sweep_supported:u8`.
   Step and decomposition identities and versions are nonzero; maximum count
   is in `1..16,384`; the Boolean is `0` or `1`.
6. `mode_count:u16`, then mode declarations sorted by `(mode_id,version)`. Each
   declaration is `mode_id:u32, version:u16, required_capability_count:u16`,
   sorted required capability entries `capability_id:[16], version:u16`,
   `scheme_count:u16`, sorted schemes `scheme_id:u32, version:u16`,
   `replay_present:u8`, then the fixed replay fields
   `replay_abi_id:u32, replay_abi_version:u16, max_input_spans:u16,
   max_prior_state_bytes:u32, max_output_bytes:u32, max_next_state_bytes:u32,
   max_authentication_path_nodes:u16, max_opening_bytes:u32,
   allowed_account_roles:u32, max_svm_cu:u64`. If replay is absent, all replay
   fields are zero. If present, replay ABI ID/version and opening maximum are
   nonzero; the opening maximum is at most 4 KiB. Account-role bits are
   application-registered; unknown bits are refused by the image manifest.
7. Resource limits, in order:
   `max_input_bytes:u32, max_output_bytes:u32, max_operations:u32,
   max_accounts:u16, max_cu:u64, max_heap_bytes:u32, max_stack_bytes:u32,
   max_concurrent_live_states:u32, max_live_state_bytes:u32`.
8. `error_mapping_count:u16`, then error mappings sorted by
   `condition_id:u16`: `condition_id:u16, stable_error_code:u16`. Both values
   are nonzero and each condition appears once. A kernel's malformed input,
   overflow, invalid length, forbidden alias, and domain refusal map to these
   stable codes when those conditions are possible for its ABI.

Presence bytes and Booleans are exactly zero or one. Records are exact-length;
all variable lengths are checked before reading. Manifest IDs are not inferred
from a source path or local build directory. `implementation_id` and
`app_image_id` are 32-byte identities supplied by the reproducible build
process. The proposed manifest root is
`SHA256(ASCII("dcg.kernel.manifest.id.v2") || 0x00 || canonical_DCKC_bytes)`.
This is a flat domain-separated hash, not a Merkle tree.

The `DCKC` byte layout and its extra field choices are proposed because the
shared draft specifies capability contents but no record codec. Director
confirmation is required before another implementation treats it as frozen.

## 5. Identity and commitment hashes

All concatenated digests are raw 32-byte values. Domain labels below are the
ASCII bytes shown followed by one zero byte. No display hex is hashed.

| Identity | Exact preimage |
|---|---|
| Graph ID | `"dcg.graph.id.v2\0" || canonical_DCGG_bytes` |
| Plan ID | `"dcg.plan.id.v2\0" || canonical_DCPL_bytes` |
| Template ID | `"dcg.template.id.v2\0" || graph_id[32] || plan_id[32] || app_image_id[32] || kernel_manifest_root[32]` |
| Kernel manifest root | `"dcg.kernel.manifest.id.v2\0" || canonical_DCKC_bytes` |
| Run ID | `"dcg.run.id.v2\0" || template_id[32] || client_nonce[32] || external_input_count:u32 || external_input_refs[]` |

Every row is SHA-256 of its preimage. For the run identity, each fixed-width
external input reference is
`external_id:u32, layout_id:u32, layout_version:u16, scheme_id:u32,
scheme_version:u16, byte_length:u32, value_digest:[32]` (52 bytes), sorted by
ascending `external_id`, with no duplicate ID. The `u32` count is a proposed
explicit delimiter selected because the shared draft only says the references
are fixed-width and sorted.

`ValueRefV1` is `node_id:u32, direction:u8, port_id:u16, layout_id:u32,
layout_version:u16, scheme_id:u32, scheme_version:u16, byte_length:u32,
value_digest:[32]` (55 bytes). `ChildRootV1` is
`child_region_id:u32, mode_id:u32, mode_version:u16, scheme_id:u32,
scheme_version:u16, layout_id:u32, layout_version:u16, child_root:[32]`
(54 bytes).

The step leaf preimage is, in order:
`plan_id:[32], run_id:[32], region_id:u32,
coordinate=(region_id:u32,segment_id:u32,ordinal:u64,node_id:u32,kernel_step:u32),
input_count:u16, input_refs[ValueRefV1], output_count:u16,
output_refs[ValueRefV1], prior_state_digest:[32], next_state_digest:[32]`.
Input and output refs sort by `(node_id,direction,port_id)`. Stateless kernels
use all-zero prior/next state digests. The leaf is
`SHA256("dcg.region.leaf.v2\0" || preimage)`.

For each Merkle parent, encode
`level:u16 || left:[32] || right:[32]` and hash
`SHA256("dcg.region.node.v2\0" || encoding)`. `level` is zero for the first
parent layer and increases by one per layer. If a layer has an odd number of
children, duplicate the last child as its right child. The first profile has
no empty region tree.

`RegionRootV1` is the exact no-padding concatenation:
`plan_id:[32], run_id:[32], region_id:u32, mode_id:u32, mode_version:u16,
scheme_id:u32, scheme_version:u16, layout_id:u32, layout_version:u16,
input_count:u16, input_refs[ValueRefV1], step_tree_root:[32], child_count:u16,
children[ChildRootV1], output_count:u16, output_refs[ValueRefV1],
final_state_digest:[32]`. Input/output references use the same ordering as a
leaf; child records sort by `child_region_id`. Its root is
`SHA256("dcg.region.root.v2\0" || canonical_RegionRootV1_bytes)`.

`app_image_id` is the externally supplied reproducible build identity for the
exact statically linked image. This codec does not prescribe a hash of a
toolchain bundle. `kernel_manifest_root` is derived from DCKC as above.

## 6. Designed ceilings and refusal boundaries

The following ceilings come from the shared draft §2.3. They are admission
limits, not measured capacities.

| Object/property | Maximum |
|---|---:|
| Region-tree depth, including root | 8 |
| Nodes / regions / edges | 4,096 / 256 / 16,384 |
| Declared ports | 16,384 |
| Port rank / max port bytes | 8 / 1 MiB |
| Parameter bytes per node | 64 KiB |
| Canonical graph / plan bytes | 4 MiB each |
| Plan steps | 16,384 |
| One replay opening | 4 KiB |

The edge count ceiling is not attainable together with the port ceiling under
the whole-port edge rule: every edge consumes a distinct destination input
port, and at least one output port is required, so at most 16,383 distinct
edges can be represented with 16,384 total ports. The vectors exercise that
maximum structurally possible count and separately exercise refusal above the
declared edge count. The unreachable `16,384` exact-edge boundary is left for
the director to reconcile with the port ceiling.

Every count, record size, port product, offset, and total envelope size uses
checked arithmetic. Oversize or unrepresentable values refuse before an
allocation proportional to the claimed length. Segment opening and cost
ceilings are validated independently; they are not CU evidence.

## 7. Python reference and goldens

The reference is `python/dcg/graph/v2.py`. `encode_graph` and `decode_graph`
implement DCGG; `encode_plan` and `decode_plan` implement DCPL. The module also
implements the proposed identity hashes and the region leaf/node/root
encodings. It is pure Python and uses only the standard library.

Golden TSVs live in `tests/golden/dcg/graph_plan_v2/`. The generator is
`scripts/dcg_graph_plan_v2_goldens.py`:

```sh
cd python
PYTHONPATH=. python ../scripts/dcg_graph_plan_v2_goldens.py --write
PYTHONPATH=. pytest -q tests/test_graph_plan_v2.py
```

Valid vector rows store the complete canonical bytes in base64. Refusal rows
store the complete malformed input bytes and the expected stable refusal
code. Tests decode and re-encode valid rows, run each refusal through the
decoder, and compare regenerated TSV bytes exactly. No network or Rust tool is
needed.

`hashes_v1.tsv` stores full hash preimages and expected SHA-256 digests for all
eight domains: graph ID, plan ID, template ID, kernel-manifest root, run ID,
step leaf, Merkle node, and region root.

The suite includes the minimal two-level optimistic graph (child `add_i32/1`,
parent `identity_i32/1`), declared profile-size boundaries, the maximal
port-compatible edge count, the 4 MiB graph and plan endpoints, and malformed
headers, records, ordering, references, shapes, trees, DAGs, segments, costs,
and openings. The canonical `DCKC` manifest for the two pure kernels has its
own byte-for-byte golden and round-trip test.

## 8. Choices needing confirmation

The shared draft is intentionally a planning interface, not a complete codec.
This freeze proposal made the following byte-level choices for director review:

1. Body-length fields count bytes after the full fixed header; the plan's body
   includes its compiler parameter bytes.
2. The run reference is 52 bytes and has an explicit `u32` count before the
   sorted records. The shared draft did not specify its fields or delimiter.
3. Step leaf bytes include `region_id` both as a direct leaf field and within
   the supplied step coordinate, matching the two listed bindings literally.
4. Merkle first-parent level is zero. The shared draft required `level:u16`
   but did not pick its origin.
5. Stateless boundaries use cursor schema `(0,0)`. Stateful cursor meaning and
   the run-record cursor value remain owned by the cursor ABI.
6. A plan has exactly one cost row per step, per region, and one run row;
   run unused keys are zero. The draft names scope kinds but not multiplicity.
7. DCKC is a proposed envelope and record schema because §4.1 lists semantic
   fields without an encoding. Its field order, byte-order/mutability/alias
   codes, account-role bit assignments, stable-error mapping shape, and flat
   manifest hash domain need confirmation. The proposed manifest ceiling is
   4 MiB with at most 4,096 kernels, chosen to bound the reference codec.
8. Registry-owned mode, scheme, layout, port-layout, decomposition,
   admission-rule, replay, state-schema and capability IDs must be assigned by
   the shared registries. Unknown graph profile modes/schemes/layouts refuse.
9. The checkpointed layout's exact parameters, complete state component
   encoding, initial root, checkpoint coordinate list and terminal replay ABI
   are not defined by the shared draft; Python graph/plan bytes preserve the
   versioned parameter payloads but do not claim to validate that ABI.
10. Kernel/image identity derivation, mode-specific parameter validation,
    detailed cost admission against a real program image, run record bytes,
    and fixed-index shard account bytes remain outside this graph/plan codec.
11. The stated 16,384 edge ceiling conflicts with 16,384 ports under the
    one-source-per-input rule; the maximum representable edge count is 16,383.

Until these choices are confirmed, the vectors freeze this proposed reference
profile for stages 2–4 to review; they are not evidence of an on-chain
implementation or capability.
