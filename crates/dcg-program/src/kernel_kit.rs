// SPDX-License-Identifier: GPL-3.0-only

//! The kernel kit (alpha plan E2 and C3).
//!
//! - [`KernelDecl`]: one way to declare an application kernel's manifest, with
//!   the port and resource limits stated once and checked at compile time.
//! - [`step_kernel_call`] and [`judge_outcome`]: the exact calls the program
//!   makes into an application kernel, for a v2.1 STEP replay and for a
//!   stateful v3 transition. The program and the conformance harness share
//!   them, so the harness tests the program's own judgement of a kernel.
//! - [`conformance`] (host only): a line protocol that runs those calls on
//!   request. The Python kit (`dcg.kernel_kit`) drives it with generated
//!   inputs and compares each answer with the kernel's Python mirror.

use crate::kernel::{
    AccountSpan, ApplicationManifest, KernelCapabilities, KernelError, KernelId, KernelManifest, ModeId,
    PortLayout, ResourceLimits, StateSchema, TransitionDisposition, TransitionOutcome, VersionedId,
    MAX_DECLARED_KERNEL_COMPUTE_UNITS, MODE_STEP_V21,
};

/// A kernel manifest declared once: each port's limit is also its resource
/// limit, so the two cannot disagree. `build` checks the declaration at
/// compile time when used in a `static`:
///
/// ```ignore
/// static MANIFEST: KernelManifest = KernelDecl::new("my-kernel-v1", 1, 1)
///     .input(VersionedId { id: 1, version: 1 }, 64)
///     .output(VersionedId { id: 2, version: 1 }, 32)
///     .compute(10_000, 1)
///     .modes(&[MODE_STEP_V21])
///     .build();
/// ```
#[derive(Clone, Copy)]
pub struct KernelDecl {
    manifest: KernelManifest,
}

const NO_PORT: PortLayout = PortLayout {
    id: VersionedId { id: 0, version: 0 },
    max_bytes: 0,
    alignment: 1,
};

impl KernelDecl {
    /// A kernel named by up to 16 bytes of UTF-8 (padded with NULs), with
    /// nonzero semantic and ABI versions.
    pub const fn new(name: &str, semantic_version: u16, abi_version: u16) -> Self {
        let raw = name.as_bytes();
        assert!(!raw.is_empty() && raw.len() <= 16, "a kernel name is 1 to 16 bytes");
        let mut id = [0u8; 16];
        let mut i = 0;
        while i < raw.len() {
            assert!(raw[i] != 0, "a kernel name has no NUL byte");
            id[i] = raw[i];
            i += 1;
        }
        assert!(semantic_version != 0 && abi_version != 0, "kernel versions are nonzero");
        Self {
            manifest: KernelManifest {
                id: KernelId(id),
                semantic_version,
                abi_version,
                input: NO_PORT,
                output: NO_PORT,
                state: None,
                resources: ResourceLimits {
                    max_input_bytes: 0,
                    max_output_bytes: 0,
                    max_state_bytes: 0,
                    max_operations: 0,
                    max_compute_units: 0,
                },
                modes: &[],
                capabilities: KernelCapabilities::NONE,
            },
        }
    }

    /// The input layout and its byte limit (port and resource limit alike).
    pub const fn input(mut self, layout: VersionedId, max_bytes: u32) -> Self {
        self.manifest.input = PortLayout { id: layout, max_bytes, alignment: 1 };
        self.manifest.resources.max_input_bytes = max_bytes;
        self
    }

    /// The output layout and its byte limit (port and resource limit alike).
    pub const fn output(mut self, layout: VersionedId, max_bytes: u32) -> Self {
        self.manifest.output = PortLayout { id: layout, max_bytes, alignment: 1 };
        self.manifest.resources.max_output_bytes = max_bytes;
        self
    }

    /// A stateful kernel's state schema and its byte limit.
    pub const fn state(mut self, schema: VersionedId, max_bytes: u32) -> Self {
        self.manifest.state = Some(StateSchema { id: schema, max_bytes });
        self.manifest.resources.max_state_bytes = max_bytes;
        self
    }

    /// The declared compute ceiling per call and the operation limit.
    pub const fn compute(mut self, max_compute_units: u64, max_operations: u32) -> Self {
        self.manifest.resources.max_compute_units = max_compute_units;
        self.manifest.resources.max_operations = max_operations;
        self
    }

    pub const fn modes(mut self, modes: &'static [ModeId]) -> Self {
        self.manifest.modes = modes;
        self
    }

    /// Declare `KernelCapabilities::REJECTS_INPUT` (design
    /// `session-reject-and-ring-v1.md` §2.1).
    pub const fn rejects_input(mut self) -> Self {
        self.manifest.capabilities = KernelCapabilities(self.manifest.capabilities.0 | KernelCapabilities::REJECTS_INPUT.0);
        self
    }

    /// The finished manifest. Panics (at compile time in a `static`) on an
    /// incomplete declaration.
    pub const fn build(self) -> KernelManifest {
        let m = self.manifest;
        assert!(m.input.id.id != 0 && m.input.id.version != 0, "declare the input layout");
        assert!(m.output.id.id != 0 && m.output.id.version != 0, "declare the output layout");
        assert!(m.input.max_bytes != 0 && m.output.max_bytes != 0, "a kernel has nonzero port limits");
        assert!(m.resources.max_operations != 0, "a kernel allows at least one operation");
        let mut i = 0;
        let mut consensus_v3 = false;
        while i < m.modes.len() {
            consensus_v3 |= m.modes[i].id == crate::stateful::v3::MODE_CONSENSUS_V3.id
                && m.modes[i].version == crate::stateful::v3::MODE_CONSENSUS_V3.version;
            i += 1;
        }
        assert!(!consensus_v3 || m.state.is_some(), "a consensus-v3 kernel declares its state");
        assert!(!m.capabilities.rejects_input() || m.state.is_some(), "only a stateful kernel rejects inputs");
        assert!(!m.modes.is_empty(), "a kernel declares at least one mode");
        assert!(m.resources.max_compute_units != 0, "declare the compute ceiling");
        assert!(
            m.resources.max_compute_units <= MAX_DECLARED_KERNEL_COMPUTE_UNITS,
            "the compute ceiling exceeds one transaction"
        );
        m
    }
}

/// What the program finds when a v2.1 STEP claim names an application kernel.
pub enum StepCall {
    /// No kernel in the image's manifest has this id and these versions and
    /// advertises `MODE_STEP_V21` (review 10-03, F2).
    NotStepKernel,
    /// The kernel refused the inputs. The claim rules for the challenger.
    Refused(KernelError),
    /// The kernel's output buffer (the output port's limit) and the length
    /// it reported. `output()` slices it exactly as the program does.
    Output { buffer: Vec<u8>, len: usize },
}

impl StepCall {
    /// The output bytes. Panics if the kernel reported more bytes than its
    /// buffer holds, as the program's slice does (the instruction aborts).
    pub fn output(&self) -> Option<&[u8]> {
        match self {
            StepCall::Output { buffer, len } => Some(&buffer[..*len]),
            _ => None,
        }
    }
}

/// Resolve and run an application kernel for one STEP replay: exact id and
/// versions, `MODE_STEP_V21` required, each input one span of the kernel's
/// input layout, and an output buffer of the output port's limit.
pub fn step_kernel_call<T: AsRef<[u8]>>(
    app: &ApplicationManifest,
    id: KernelId,
    semantic_version: u16,
    abi_version: u16,
    inputs: &[T],
) -> StepCall {
    let Some(kernel) = app
        .resolve(id, semantic_version, abi_version)
        .filter(|k| k.manifest().modes.contains(&MODE_STEP_V21))
    else {
        return StepCall::NotStepKernel;
    };
    let m = kernel.manifest();
    let spans: Vec<AccountSpan> = inputs
        .iter()
        .map(|v| AccountSpan {
            key: [0; 32],
            owner: [0; 32],
            is_signer: false,
            is_writable: false,
            schema: m.input.id,
            offset: 0,
            data: v.as_ref(),
        })
        .collect();
    let mut buffer = vec![0u8; m.output.max_bytes as usize];
    match kernel.execute_spans(&spans, &mut buffer) {
        Err(e) => StepCall::Refused(e),
        Ok(len) => StepCall::Output { buffer, len },
    }
}

/// How the stateful v3 runtime treats one transition result it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judged {
    Continue,
    HaltBefore(u32),
    HaltAfter(u32),
    Reject(u32),
}

/// The v3 runtime's judgement of one kernel transition outcome; `None` means
/// the runtime refuses the whole advance (`REFUSAL_KERNEL`). `rejectable` is
/// the session's flag and the kernel's declared capability together;
/// `state_changed` reports whether the state differs from before the call
/// (the runtime checks this only at or below its snapshot cap).
pub fn judge_outcome(
    outcome: TransitionOutcome,
    rejectable: bool,
    output_len: usize,
    state_changed: impl FnOnce() -> bool,
) -> Option<Judged> {
    if outcome.output_bytes > output_len {
        return None;
    }
    match outcome.disposition {
        TransitionDisposition::Continue => Some(Judged::Continue),
        TransitionDisposition::HaltBefore { reason } => {
            (reason != 0 && !state_changed()).then_some(Judged::HaltBefore(reason))
        }
        TransitionDisposition::HaltAfter { reason } => (reason != 0).then_some(Judged::HaltAfter(reason)),
        // Only a session opened rejectable (its kernel declares the
        // capability) may reject; the input is consumed with state and output
        // untouched (design session-reject-and-ring-v1 §2.2).
        TransitionDisposition::Reject { code } => {
            (rejectable && code != 0 && outcome.output_bytes == 0 && !state_changed()).then_some(Judged::Reject(code))
        }
    }
}

/// The v3 runtime's output buffer for a kernel: the smaller of the output
/// port and resource limits, refused when zero or above 64 KiB.
pub fn v3_output_len(manifest: &KernelManifest) -> Option<usize> {
    let len = (manifest.output.max_bytes as usize).min(manifest.resources.max_output_bytes as usize);
    (len != 0 && len <= 65_536).then_some(len)
}

#[cfg(not(target_os = "solana"))]
pub mod conformance {
    //! The conformance server: one request per line on standard input, one
    //! answer per line on standard output. Bytes are lowercase hex, `-` for
    //! empty. Requests:
    //!
    //! - `manifest <id> <semver> <abi>`
    //! - `step <id> <semver> <abi> <input>...` (zero or more input spans;
    //!   `builtin` for a built-in kernel or reduction name)
    //! - `init <id> <semver> <abi> <span lengths, comma separated>`
    //! - `advance <id> <semver> <abi> <rejectable 0|1> <span lengths> <state> <input>`
    //!
    //! `step` runs [`super::step_kernel_call`]; `init` and `advance` run a
    //! stateful kernel the way the v3 runtime does (state spans at
    //! consecutive offsets, invocation binding, the output buffer of
    //! [`super::v3_output_len`], [`super::judge_outcome`] with the runtime's
    //! snapshot cap). Answers are documented on each handler. The server
    //! does not model account plumbing, session admission or the per-advance
    //! compute budget; those are tested by running the program.

    use super::*;
    use crate::kernel::{StateSpanMut, StatefulKernel};
    use crate::stateful::v3::HALT_BEFORE_RUNTIME_CHECK_BYTES;
    use std::io::{BufRead, Write};

    pub struct Registry<'a> {
        /// The image's application manifest (STEP kernels), if it has one;
        /// a session-only application passes `None`.
        pub app: Option<&'a ApplicationManifest>,
        pub stateful: &'a [&'static dyn StatefulKernel],
    }

    /// Serve requests until end of input.
    pub fn serve(registry: &Registry<'_>, input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let answer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| answer(registry, &line)))
                .unwrap_or_else(|_| "panic".to_string());
            writeln!(output, "{answer}")?;
            output.flush()?;
        }
        Ok(())
    }

    /// Answer one request line.
    pub fn answer(registry: &Registry<'_>, line: &str) -> String {
        match handle(registry, line) {
            Ok(answer) => answer,
            Err(message) => format!("error {message}"),
        }
    }

    fn handle(registry: &Registry<'_>, line: &str) -> Result<String, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        let (verb, rest) = words.split_first().ok_or("empty request")?;
        let [id, sv, av, rest @ ..] = rest else {
            return Err("expected <id> <semver> <abi>".into());
        };
        let id = KernelId(unhex(id)?.try_into().map_err(|_| "a kernel id is 16 bytes")?);
        let sv: u16 = sv.parse().map_err(|_| "bad semantic version")?;
        let av: u16 = av.parse().map_err(|_| "bad ABI version")?;
        match *verb {
            "manifest" => manifest(registry, id, sv, av),
            // A built-in reduction or kernel name shadows any application
            // kernel: the referee rules on the built-in (or for the
            // challenger at another version) before the manifest is read.
            "step" if crate::kernel::is_builtin_kernel_name(&id.0) => Ok("builtin".into()),
            "step" => {
                let inputs = rest.iter().map(|w| unhex(w)).collect::<Result<Vec<_>, _>>()?;
                let Some(app) = registry.app else { return Ok("not-step".into()) };
                Ok(match step_kernel_call(app, id, sv, av, &inputs) {
                    StepCall::NotStepKernel => "not-step".into(),
                    StepCall::Refused(e) => format!("refused {e:?}"),
                    call => format!("output {}", hex(call.output().unwrap())),
                })
            }
            "init" => {
                let [lens] = rest else { return Err("expected <span lengths>".into()) };
                let Some(kernel) = stateful(registry, id, sv, av) else { return Ok("not-stateful".into()) };
                init(kernel, &lengths(lens)?)
            }
            "advance" => {
                let [rejectable, lens, state, input] = rest else {
                    return Err("expected <rejectable> <span lengths> <state> <input>".into());
                };
                let Some(kernel) = stateful(registry, id, sv, av) else { return Ok("not-stateful".into()) };
                let rejectable = match *rejectable {
                    "0" => false,
                    "1" => true,
                    _ => return Err("rejectable is 0 or 1".into()),
                };
                advance(kernel, rejectable, &lengths(lens)?, unhex(state)?, &unhex(input)?)
            }
            _ => Err(format!("unknown request {verb}")),
        }
    }

    fn stateful(registry: &Registry<'_>, id: KernelId, sv: u16, av: u16) -> Option<&'static dyn StatefulKernel> {
        registry.stateful.iter().copied().find(|k| {
            let m = k.manifest();
            m.id == id && m.semantic_version == sv && m.abi_version == av
        })
    }

    /// `ok key=value ...` with the declared limits (port/resource), or
    /// `unknown`.
    fn manifest(registry: &Registry<'_>, id: KernelId, sv: u16, av: u16) -> Result<String, String> {
        let stateful = stateful(registry, id, sv, av);
        let m = match (registry.app.and_then(|a| a.resolve(id, sv, av)), stateful) {
            (Some(k), _) => k.manifest(),
            (None, Some(k)) => k.manifest(),
            (None, None) => return Ok("unknown".into()),
        };
        let modes: Vec<String> = m.modes.iter().map(|m| format!("{:08x}.{}", m.id, m.version)).collect();
        Ok(format!(
            "ok input={}/{} output={}/{} state={}/{} operations={} compute={} capabilities={} modes={} stateful={}",
            m.input.max_bytes,
            m.resources.max_input_bytes,
            m.output.max_bytes,
            m.resources.max_output_bytes,
            m.state.map_or("-".to_string(), |s| s.max_bytes.to_string()),
            m.resources.max_state_bytes,
            m.resources.max_operations,
            m.resources.max_compute_units,
            m.capabilities.0,
            if modes.is_empty() { "-".to_string() } else { modes.join(",") },
            stateful.is_some() as u8,
        ))
    }

    fn spans_over<'a>(
        manifest: &KernelManifest,
        lens: &[u32],
        state: &'a mut [u8],
    ) -> Result<Vec<StateSpanMut<'a>>, String> {
        let schema = manifest.state.ok_or("the kernel declares no state")?.id;
        let mut spans = Vec::with_capacity(lens.len());
        let mut rest = state;
        let mut offset = 0u32;
        for &len in lens {
            let (head, tail) = rest.split_at_mut(len as usize);
            spans.push(StateSpanMut { key: [0; 32], owner: [0; 32], schema, offset, data: head });
            offset += len;
            rest = tail;
        }
        Ok(spans)
    }

    /// `state <hex>`, `refused kernel <error>`, or `refused written <n>`
    /// when the kernel reports a byte count other than the state's size.
    fn init(kernel: &'static dyn StatefulKernel, lens: &[u32]) -> Result<String, String> {
        let total: u32 = lens.iter().sum();
        let mut state = vec![0u8; total as usize];
        let mut spans = spans_over(kernel.manifest(), lens, &mut state)?;
        let bind = kernel.bind_invocation_state(&mut spans);
        let init = bind.and_then(|()| kernel.initial_state_spans_with_resources(&[], &[0; 32], &mut spans));
        kernel.unbind_invocation_state();
        drop(spans);
        Ok(match init {
            Err(e) => format!("refused kernel {e:?}"),
            Ok(written) if written != total as usize => format!("refused written {written}"),
            Ok(_) => format!("state {}", hex(&state)),
        })
    }

    /// `<raw> judged <verdict>` where raw is
    /// `<continue|halt_before|halt_after|reject> <code> <output> <state>` or
    /// `failed <kernel error>`, and the verdict is `accepted` or `refused`.
    /// The raw output is `-` when the kernel reports more bytes than the
    /// buffer, which the runtime refuses.
    fn advance(
        kernel: &'static dyn StatefulKernel,
        rejectable_session: bool,
        lens: &[u32],
        mut state: Vec<u8>,
        input: &[u8],
    ) -> Result<String, String> {
        let manifest = kernel.manifest();
        if lens.iter().map(|l| *l as usize).sum::<usize>() != state.len() {
            return Err("the state does not match its span lengths".into());
        }
        let Some(output_len) = v3_output_len(manifest) else { return Ok("failed OutputLimit judged refused".into()) };
        let rejectable = rejectable_session && manifest.capabilities.rejects_input();
        let before = (state.len() <= HALT_BEFORE_RUNTIME_CHECK_BYTES).then(|| state.clone());
        let mut output = vec![0u8; output_len];
        let mut spans = spans_over(manifest, lens, &mut state)?;
        let bind = kernel.bind_invocation_state(&mut spans);
        let result = bind.and_then(|()| kernel.transition_spans_with_outcome(input, &mut spans, &mut output));
        kernel.unbind_invocation_state();
        drop(spans);
        let outcome = match result {
            Err(e) => return Ok(format!("failed {e:?} judged refused")),
            Ok(outcome) => outcome,
        };
        let changed = || before.as_ref().is_some_and(|b| *b != state);
        let verdict = match judge_outcome(outcome, rejectable, output_len, changed) {
            Some(_) => "accepted",
            None => "refused",
        };
        let (kind, code) = match outcome.disposition {
            TransitionDisposition::Continue => ("continue", 0),
            TransitionDisposition::HaltBefore { reason } => ("halt_before", reason),
            TransitionDisposition::HaltAfter { reason } => ("halt_after", reason),
            TransitionDisposition::Reject { code } => ("reject", code),
        };
        let out = output.get(..outcome.output_bytes).map_or("-".to_string(), hex);
        Ok(format!("{kind} {code} {out} {} judged {verdict}", hex(&state)))
    }

    fn lengths(word: &str) -> Result<Vec<u32>, String> {
        word.split(',').map(|w| w.parse().map_err(|_| format!("bad span length {w}"))).collect()
    }

    pub fn hex(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "-".into();
        }
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn unhex(word: &str) -> Result<Vec<u8>, String> {
        if word == "-" {
            return Ok(Vec::new());
        }
        if word.len() % 2 != 0 {
            return Err("odd hex length".into());
        }
        (0..word.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&word[i..i + 2], 16).map_err(|_| "bad hex".to_string()))
            .collect()
    }
}
