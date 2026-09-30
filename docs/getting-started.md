# Getting started with DCG

This first-hour path follows the static kernel contract and app manifest, then
runs tests against the extracted revision-8 handlers. It does not claim a full
SBF document lifecycle: the only existing SBF lifecycle harness is the
isolated, test-feature canary described at the end.

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
ProgramTest run through the revision-8 registry/admission, document,
challenge/response, settlement, resolution, and close handlers.
