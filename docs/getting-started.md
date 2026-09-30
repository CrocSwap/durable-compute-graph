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
};
```

Call `ApplicationManifest::validate` during app setup. Link the selected
manifest into the image and call `process_instruction_with_manifest` from the
app entrypoint. The default standalone image has an empty app manifest and no
test kernel.

## 3. Declare authenticated account regions

Each `AccountSpanBinding` names an account index, owner rule, signer/writable
role, versioned schema, and checked offset and length. The SVM adapter verifies
all descriptors and bounds before borrowing any account data. It rejects
overlapping regions and any duplicate account key when either span is
writable. Disjoint read-only regions of one account are allowed. The view
passed to a kernel carries the account key, owner, roles, schema, offset, and
bounded bytes.

The revision-8 challenge handler first authenticates the plan accounts and
fix-point coordinate. An application binding can then route that point through
its exact manifest kernel. `ByteSum` demonstrates this as a pure byte kernel;
the SVM adapter keeps `AccountInfo` out of its computation contract.

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

The measured image on 2026-09-30 was 751,280 bytes with SHA-256
`80cbc43ba99da10cabf071fa4d6769b546dad73f8431f7bcce9a32a2e6fad2bf`.
The feature binds retained machine selector 1 / Form 256 to ByteSum with exact
semantic version 1, ABI version 1, optimistic mode 1, and two authenticated
read-only spans. These bindings and the extra form are absent from the default
image.

The real SBF transaction driver uses the retained revision-8 fixture builders
in a Basanos checkout because those large fixture builders are not included in
this extraction. Point `BASANOS_CHECKOUT` at that checkout and set
`BASANOS_PT2P_ROOT` to the retained K=80 fixture, then run a focused ProgramTest
case against the image:

```sh
BASANOS_DCG_V8_SBF=1 BPF_OUT_DIR=/private/tmp/dcg-sbf-real BASANOS_PT2P_ROOT="$PT2P_ROOT_K80" CARGO_TARGET_DIR=/private/tmp/basanos-test-target cargo test --locked --offline --profile fasttest --manifest-path "$BASANOS_CHECKOUT/chain/dcg-program/Cargo.toml" --test unified_v8_document rev8_position_challenge_rounds_reach_an_admitted_fixpoint -- --nocapture
```

That existing test reaches the ByteSum fix-point replay. The measured round-5
run also used temporary focused tests for the K=10,240 registry/admission and
honest resolve/close path, plus a ByteSum replay, wrong-role refusal, executor
timeout, settlement, and close path. The temporary test driver and its exact
measurements are documented in the experiment note. No Basanos source was
changed. Treat all results as mechanics demonstrations; the input stream,
engine-state accounts, views, and session close remain open stateful features.
