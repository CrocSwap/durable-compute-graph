# Getting started with DCG

This guide follows the `ByteSum` test kernel through the static kernel
contract, application manifest, reproducible SBF build, and full optimistic
lifecycle canary. The canary is a mechanics demonstration. It defines no
production graph or sweep format and says nothing about model quality.

## 1. Define a kernel

Implement `Kernel` over authenticated canonical byte inputs. Keep the
computation deterministic, bound input and output lengths from the manifest,
and write canonical output bytes. The test implementation in
[`kernel.rs`](../crates/dcg-program/src/kernel.rs) is a complete small example.

```rust
impl Kernel for MyKernel {
    fn manifest(&self) -> &'static KernelManifest {
        &MY_KERNEL_MANIFEST
    }

    fn execute(&self, input: &[u8], output: &mut [u8]) -> Result<usize, KernelError> {
        // Validate the canonical input, perform bounded deterministic work,
        // write the canonical output, and return the number of bytes written.
        todo!()
    }
}
```

The manifest pins a kernel ID, semantic version, ABI version, input and output
layouts, optional state schema, resource limits, and enabled versioned modes.
Implement `StatefulKernel` only if the transition owns state. Implement
`OptimisticReplay` only for modes where the application can re-execute a
disputed step from authenticated inputs and compare the claimed output and
state.

## 2. Register the kernel in an application manifest

Keep the kernel, manifest, and replay binding in static application data. A
replay binding names both the exact kernel implementation and the versioned
mode for which replay is allowed.

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
};
```

Call `ApplicationManifest::validate` during application setup. Resolution
backends implement `ResolutionBackend` separately; they own admission,
challenge transitions, and status. The byte kernel contract does not include
SVM account types or load code dynamically.

## 3. Build the SBF lifecycle image

Use the pinned platform-tools SDK root. It must contain
`dependencies/platform-tools`; the tools-version flag alone is not a toolchain
pin. The wrapper checks for SBF stack-frame warnings and cleans its staging
copy on exit.

```sh
export CARGO_TARGET_DIR=/private/tmp/dcg-target
export DCG_SBF_SDK=/path/to/platform-tools-sdk
export DCG_SBF_TOOLS_VERSION=v1.51
export DCG_SBF_STAGING_NAME=dcg-sbf-first-hour

crates/dcg-program/scripts/build-sbf-reproducible.sh \
  --features sbf-lifecycle-test \
  --sbf-out-dir /private/tmp/dcg-sbf
```

`cargo-build-sbf` must be installed, or set `DCG_CARGO_BUILD_SBF` to its
executable path. The feature links `ByteSum` and the isolated lifecycle
instructions into the test image. It does not enable those instructions in the
default program image.

## 4. Run the ProgramTest lifecycle

Point ProgramTest at the image just built:

```sh
SBF_OUT_DIR=/private/tmp/dcg-sbf \
CARGO_TARGET_DIR=/private/tmp/dcg-target \
cargo test --locked --profile fasttest -p dcg-program \
  --features sbf-lifecycle-test \
  --test bytesum_sbf_lifecycle -- --nocapture
```

The test uses a local Solana ProgramTest runtime. It first sends one malformed
input for each lifecycle stage, then runs:

- an honest template registration, admission, document initialization, root
  landing, finalization, resolution, and close with a rent refund;
- a dishonest claimed output, challenge, two bisection rounds, on-chain
  `OptimisticReplay`, settlement against the cheater, and close.

Each measured transaction contains one lifecycle program instruction. The
test prints `SBF_CU|stage|units` from ProgramTest transaction metadata. The
four-entry trace and its instruction tags exist only for this test harness;
they are not a DCG or Basanos wire format. See the
[`measured lifecycle record`](experiments/bytesum-sbf-lifecycle-2026-09-30.md)
for the current image digest, tool versions, and CU table.
