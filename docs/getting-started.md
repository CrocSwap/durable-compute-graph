# Getting started with DCG

This first-hour path follows the static kernel contract and app manifest, then
runs tests against the extracted revision-8 handlers. The optional real-SBF
path at the end is a test-only mechanics demonstration using retained
Basanos fixtures; it does not establish model quality or ship-ready behavior.

## 1. Define a kernel

Implement `Kernel` over deterministic canonical bytes. Keep input and output
lengths within the manifest limits. A byte-only kernel uses the convenient
single-slice method; a kernel that reads several committed account regions can
override `execute_spans` or `replay_spans`.

```rust
impl Kernel for MyKernel {
    fn manifest(&self) -> &'static KernelManifest {
        &MY_KERNEL_MANIFEST
    }

    fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
        // Validate canonical input, perform bounded deterministic work,
        // write canonical output, and return the number of bytes written.
        todo!()
    }
}
```

The manifest pins `KernelId`, semantic version, ABI version, input and output
layouts, optional state schema, resource limits, and enabled versioned modes.
Implement `StatefulKernel` only if the transition owns state. Implement
`OptimisticReplay` only for modes where one disputed transition fits one SVM
instruction.

## 2. Bind the kernel in the application image

Keep kernel implementations, replay bindings, and legacy-form selections in
static application data. `LegacyFormBinding` maps a frozen revision-8
`(machine selector, form id)` to an exact kernel semantic version, ABI version,
and mode. It changes no revision-8 record or instruction bytes. When an app
requires these bindings, an unbound form or unavailable kernel identity is
refused. An app that supplies no bindings retains the revision-8 compatibility
adapter.

```rust
static KERNELS: [&'static dyn Kernel; 1] = [&MY_KERNEL];
static REPLAY_BINDINGS: [OptimisticReplayBinding; 1] = [OptimisticReplayBinding {
    mode: MY_OPTIMISTIC_MODE,
    replay: &MY_KERNEL,
}];

static APPLICATION: ApplicationManifest = ApplicationManifest {
    application_id: b"example/app/1",
    version: 1,
    kernels: &KERNELS,
    optimistic_replays: &REPLAY_BINDINGS,
    legacy_forms: &MY_LEGACY_FORM_BINDINGS,
    require_legacy_form_binding: true,
    hooks: &MY_APPLICATION_HOOKS,
    decision_routes: &MY_DECISION_ROUTES,
};
```

Call `ApplicationManifest::validate` during app setup. Link the selected
manifest into the image and call `process_instruction_with_manifest` from the
app entrypoint. `ApplicationHooks` supplies revision-8 policy and `DecisionRouteSelector`
supplies the typed-decision producer used by tags 146, 199, and 200. The default
standalone image has an empty app manifest and no test kernel.

## 3. Commit coordinate-specific replay inputs

Each application binding names the versioned input schema, input byte limit,
kernel semantic version, ABI version, and replay mode. A canonical `ARW1`
witness carries the disputed coordinate's input slices and claimed output. Its
`app-replay-leaf/1` digest is committed into the existing ROOT_ONLY segment and
position trees. At the revision-8 fix-point, DCG checks the witness against the
proved leaf and invokes only the statically linked app kernel. A malformed
challenger preimage loses as an unproved challenge; invalid committed input or
a wrong output rules against the executor immediately. `AccountSpanBinding`
remains available for separately authenticated account views, but it is not
the source of a replay input in this app path.

## 4. Run the extracted handler tests

Use Python's caller-independent Rust profile and the locked offline dependency
set:

```sh
CARGO_TARGET_DIR=/private/tmp/dcg-target \
cargo test --locked --offline --profile fasttest -p dcg-program \
  --features test-kernel --lib kernel

CARGO_TARGET_DIR=/private/tmp/dcg-target \
cargo test --locked --offline --profile fasttest -p dcg-program \
  --test unified_v8_bond
```

The first command checks exact manifest lookup, ByteSum replay, schema and
account-span bounds, role checks, and alias refusal. The second enters the real
revision-8 program dispatcher and exercises tags 131 and 187 for settlement and
retry. Its test records are deliberately crafted for those handler slices; it
does not exercise registry/admission, document initialization, or a complete
document lifecycle.

The optional real-lifecycle binding is checked with:

```sh
CARGO_TARGET_DIR=/private/tmp/dcg-target cargo test --locked --offline --profile fasttest -p dcg-program --features sbf-real-lifecycle-test --lib kernel

CARGO_TARGET_DIR=/private/tmp/dcg-target cargo test --locked --offline --profile fasttest -p dcg-program --features sbf-real-lifecycle-test --lib kernel_svm
```

These host tests cover exact kernel identity and version lookup, the Form-256
span declaration, account roles, and alias refusal. They do not report SBF CU.

## 5. Optional isolated SBF canary

The canary is test-only behind `sbf-lifecycle-test`; it is not linked into the
default image and does not exercise the extracted revision-8 handlers. Build
with the pinned platform-tools SDK root:

```sh
export CARGO_TARGET_DIR=/private/tmp/dcg-target
export DCG_SBF_SDK=/path/to/platform-tools-sdk
export DCG_SBF_TOOLS_VERSION=v1.51
export DCG_SBF_STAGING_NAME=dcg-sbf-first-hour

crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-sbf
```

Then run its separate ProgramTest target:

```sh
SBF_OUT_DIR=/private/tmp/dcg-sbf \
CARGO_TARGET_DIR=/private/tmp/dcg-target \
cargo test --locked --profile fasttest -p dcg-program \
  --features sbf-lifecycle-test \
  --test bytesum_sbf_lifecycle -- --nocapture
```

The canary uses private tags 240–250 and a bespoke template, document, bond,
and Merkle layout. It demonstrates SBF mechanics only. It does not replace a
ProgramTest run through the revision-8 handlers.

## 6. Optional real revision-8 SBF lifecycle

Build a separate test image with the feature-gated ByteSum bindings:

```sh
export CARGO_TARGET_DIR=/private/tmp/dcg-target
export DCG_SBF_SDK=/path/to/platform-tools-sdk
export DCG_SBF_TOOLS_VERSION=v1.51
export DCG_SBF_STAGING_NAME=dcg-sbf-real-lifecycle

crates/dcg-program/scripts/build-sbf-reproducible.sh --features sbf-real-lifecycle-test --sbf-out-dir /private/tmp/dcg-sbf-real
```

Round 5 used a 751,280-byte image with SHA-256
`80cbc43ba99da10cabf071fa4d6769b546dad73f8431f7bcce9a32a2e6fad2bf`. The
expanded feature image now also links the test-only stateful counter app; its
measured size and digest are in
[`stateful-sbf-workload-2026-09-30.md`](experiments/stateful-sbf-workload-2026-09-30.md).
The feature binds retained machine selector 1 / Forms 22 and 256 to ByteSum
with semantic version 1, ABI version 1, optimistic mode 1, and a versioned
input schema. Those bindings and the extra form are absent from the default
image.

The real SBF transaction driver is retained in this repository as
`tests/unified_v8_document.rs`. It uses compact checked-in golden inputs and a
retained compiler-v1 PT2P bundle supplied through `BASANOS_PT2P_ROOT`. Point
`BPF_OUT_DIR` at the feature-built image and run a focused ProgramTest case:

```sh
BASANOS_DCG_V8_SBF=1 BPF_OUT_DIR=/private/tmp/dcg-sbf-real \
  BASANOS_PT2P_ROOT="$PT2P_ROOT_K80" \
  CARGO_TARGET_DIR=/private/tmp/dcg-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
    --features sbf-real-lifecycle-test --test unified_v8_document \
    rev8_position_challenge_rounds_reach_an_admitted_fixpoint -- --nocapture
```

The honest-input test reaches tag 169 and rules immediately for the challenger
because replay matches. The wrong-output test reaches tag 169, rules against
the executor with code 800, then runs tags 131 and 172 for settlement and
close. The round-5 K=10,240 admission and
resolve/close cases use the same target with the K=10,240 compiler-v1 bundle
selected through `BASANOS_PT2P_ROOT`. Run the permanent K=10,240 registry and
admission test:

```sh
BASANOS_DCG_V8_SBF=1 BPF_OUT_DIR=/private/tmp/dcg-sbf-real \
  BASANOS_PT2P_ROOT="$PT2P_ROOT_K10240" \
  CARGO_TARGET_DIR=/private/tmp/dcg-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
    --features sbf-real-lifecycle-test --test unified_v8_document \
    rev8_pt1x_registry_and_admission_sbf -- --nocapture
```

Run the K=10,240 admission-through-resolve-and-close test with the same
environment and command, replacing the filter with
`rev8_pt1x_real_admission_to_resolve_sbf`:

```sh
BASANOS_DCG_V8_SBF=1 BPF_OUT_DIR=/private/tmp/dcg-sbf-real \
  BASANOS_PT2P_ROOT="$PT2P_ROOT_K10240" \
  CARGO_TARGET_DIR=/private/tmp/dcg-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
    --features sbf-real-lifecycle-test --test unified_v8_document \
    rev8_pt1x_real_admission_to_resolve_sbf -- --nocapture
```

To test that missing app bindings fail during admission, build the test-only
sentinel manifest. It binds only Form 65,535, so a real form refuses on tag 160
before a document can rely on it:

```sh
crates/dcg-program/scripts/build-sbf-reproducible.sh --features sbf-unbound-form-test --sbf-out-dir /private/tmp/dcg-sbf-unbound

BASANOS_DCG_V8_SBF=1 BPF_OUT_DIR=/private/tmp/dcg-sbf-unbound \
  BASANOS_PT2P_ROOT="$PT2P_ROOT_K80" \
  CARGO_TARGET_DIR=/private/tmp/dcg-target \
  cargo test --locked --offline --profile fasttest -p dcg-program \
    --features sbf-unbound-form-test --test unified_v8_document \
    rev8_unbound_form_refuses_admission_on_sbf -- --nocapture
```

The K=80 ByteSum wrong-output, standard settlement, and close case is
`rev8_bytesum_wrong_output_rules_and_settles_sbf`. The companion
`rev8_bytesum_malicious_challenger_loses_app_replay_sbf` and
`rev8_bytesum_malformed_committed_input_rules_executor_sbf` cover the honest
executor and malformed committed-input rules. See
[`dcg-seam-fix-2026-09-30.md`](experiments/dcg-seam-fix-2026-09-30.md) for
measured CU values, SBF image identities, and artifact provenance. No Basanos
source is required or changed.

## 7. Stateful workload on the SBF image

The local stateful prototype is specified in
[`stateful-workloads-v1.md`](stateful-workloads-v1.md). Its test app is a
two-field counter kernel with two output ABIs and one scratch span. Build the
test-only app image, then run the real handler in ProgramTest:

```sh
export CARGO_TARGET_DIR=/private/tmp/dcg-target
export DCG_SBF_SDK=/path/to/platform-tools-sdk
export DCG_SBF_TOOLS_VERSION=v1.51
export DCG_SBF_STAGING_NAME=dcg-sbf-stateful-v1

crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-real-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-sbf-stateful

SBF_OUT_DIR=/private/tmp/dcg-sbf-stateful \
CARGO_TARGET_DIR=/private/tmp/dcg-target \
cargo test --locked --offline --profile fasttest -p dcg-program \
  --features sbf-real-lifecycle-test --test stateful_sbf_workload -- --nocapture
```

The ProgramTest sends tags 230–239 against the SBF image. Its honest sessions
cover indexed and append inputs, three-step advancement, split state spans,
two outputs from one cursor, explicit anchoring, halt, and rent-refund close.
The controls refuse stale cursors, duplicate slots, wrong append sequences and
writers, mismatched view cursors, live close, wrong refund authority, aliases,
and resource limits above the manifest. The test reports CU from each
instruction's transaction metadata. The counter result is mechanics evidence,
not a Doom kernel or model-quality result.
