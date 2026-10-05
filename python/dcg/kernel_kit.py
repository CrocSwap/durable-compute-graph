"""The kernel kit (alpha plan E2 and C3): declare an application kernel's
Python mirror once, and check it against the Rust kernel on generated inputs.

A mirror is the host reference the Python client uses where the program would
run the kernel: the v2.1 referee replays STEP claims with it, and a session
client predicts state with it. A mirror that disagrees with its kernel at any
input, edge limit or refusal is a bug of the kind review finding F2 was.

Declaring:

- :func:`step_kernel` decorates ``fn(inputs: list[bytes]) -> bytes`` (raise
  :class:`KernelRefused` to refuse) and registers it for STEP replay.
- :class:`StatefulMirror` is subclassed with ``decl``, ``state_spans``,
  ``initial_state`` and ``transition``.

Checking: build the application's conformance server (a copy of
``crates/dcg-kernel-conform`` naming its kernels), then run
``python -m dcg.kernel_kit check --bin <server> <module>...``, or call
:func:`check_step` and :func:`check_stateful`. The server runs the program's
own kernel calls (``kernel_kit.rs``), and the check compares what the program
would observe: a STEP output or refusal, a transition's acceptance, its
disposition, output and next state. Error kinds are reported, not compared,
because the program treats every kernel error alike.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import random
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

KERNEL_ERRORS = ("InputTooLarge", "OutputTooSmall", "StateTooLarge", "InvalidInput", "Refused")

#: Mode identities (``kernel.rs``, ``stateful_v3.rs``).
MODE_STEP_V21 = (0x5354_4550, 1)
MODE_CONSENSUS_V3 = (0x434F_4E53, 3)

#: The v3 runtime checks that HaltBefore and Reject leave state unchanged only
#: at or below this many state bytes (``HALT_BEFORE_RUNTIME_CHECK_BYTES``).
SNAPSHOT_CHECK_BYTES = 8 * 1024


class KernelRefused(ValueError):
    """A kernel refusal. ``kind`` names a Rust ``KernelError`` variant; the
    program treats every kind alike. A ``ValueError`` from a mirror counts as
    a refusal too, so existing mirrors keep working."""

    def __init__(self, kind: str = "Refused", detail: str = ""):
        if kind not in KERNEL_ERRORS:
            raise ValueError(f"unknown kernel error kind {kind!r}")
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind


def kernel_id(name: str) -> bytes:
    """A kernel name padded with NULs to the 16-byte id (the Rust rule)."""
    raw = name.encode()
    if not 1 <= len(raw) <= 16 or b"\x00" in raw:
        raise ValueError("a kernel name is 1 to 16 bytes with no NUL")
    return raw.ljust(16, b"\x00")


@dataclass(frozen=True)
class KernelDecl:
    """A kernel's identity and limits, exactly as its Rust ``KernelDecl``
    declares them. The check compares these with the built kernel's manifest,
    so a mirror cannot silently assume different limits."""

    name: str
    max_input_bytes: int
    max_output_bytes: int
    max_compute_units: int
    max_operations: int
    modes: tuple[tuple[int, int], ...]
    semantic_version: int = 1
    abi_version: int = 1
    max_state_bytes: int | None = None
    rejects_input: bool = False

    @property
    def id(self) -> bytes:
        return kernel_id(self.name)

    @property
    def key(self) -> tuple[bytes, int, int]:
        return (self.id, self.semantic_version, self.abi_version)

    def manifest_line(self, stateful: bool) -> str:
        """The server's ``manifest`` answer this declaration implies."""
        modes = ",".join(f"{i:08x}.{v}" for i, v in self.modes) or "-"
        state = "-" if self.max_state_bytes is None else str(self.max_state_bytes)
        return (
            f"ok input={self.max_input_bytes} output={self.max_output_bytes} state={state} "
            f"operations={self.max_operations} compute={self.max_compute_units} "
            f"capabilities={int(self.rejects_input)} modes={modes} stateful={int(stateful)}"
        )


# --- stateless STEP kernels ---------------------------------------------------------------------


@dataclass(frozen=True)
class StepMirror:
    """A stateless STEP kernel's mirror. Calling it returns the one output in
    a list (the referee's registry signature) or raises on refusal."""

    decl: KernelDecl
    fn: Callable[[list[bytes]], bytes]

    def __call__(self, inputs: list[bytes]) -> list[bytes]:
        out = self.fn(list(inputs))
        if not isinstance(out, (bytes, bytearray)):
            raise TypeError("a STEP mirror returns bytes")
        return [bytes(out)]


#: STEP mirrors by (16-byte id, semantic version, ABI version), as the program
#: resolves a manifest kernel. ``dcg.disputes_v21.appkernels.REGISTRY`` is
#: this dictionary.
STEP_REGISTRY: dict[tuple[bytes, int, int], StepMirror] = {}


def step_kernel(
    name: str,
    *,
    max_input_bytes: int,
    max_output_bytes: int,
    max_compute_units: int,
    max_operations: int = 1,
    semantic_version: int = 1,
    abi_version: int = 1,
    register: bool = True,
) -> Callable[[Callable[[list[bytes]], bytes]], StepMirror]:
    """Declare a STEP kernel's mirror (``MODE_STEP_V21``) and, by default,
    register it for the v2.1 referee."""

    decl = KernelDecl(
        name=name,
        max_input_bytes=max_input_bytes,
        max_output_bytes=max_output_bytes,
        max_compute_units=max_compute_units,
        max_operations=max_operations,
        modes=(MODE_STEP_V21,),
        semantic_version=semantic_version,
        abi_version=abi_version,
    )

    def wrap(fn: Callable[[list[bytes]], bytes]) -> StepMirror:
        mirror = StepMirror(decl, fn)
        if register:
            if decl.key in STEP_REGISTRY:
                raise ValueError(f"a STEP mirror for {name} v{semantic_version}/{abi_version} is registered")
            STEP_REGISTRY[decl.key] = mirror
        return mirror

    return wrap


# --- stateful kernels ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Outcome:
    """A transition result: the kernel's output bytes, the state after the
    call, and the disposition (``continue``, ``halt_before``, ``halt_after``
    or ``reject``) with its reason or code."""

    output: bytes
    state: bytes
    disposition: str = "continue"
    code: int = 0


class StatefulMirror:
    """Base class for a stateful v3 kernel's mirror. Subclasses set ``decl``
    and ``state_spans`` (the span lengths sessions open with) and implement
    ``initial_state`` and ``transition``; both raise :class:`KernelRefused`
    to refuse. ``special_inputs`` lists commands the generator should try."""

    decl: KernelDecl
    state_spans: tuple[int, ...]
    special_inputs: tuple[bytes, ...] = ()

    def initial_state(self, spans: tuple[int, ...]) -> bytes:
        raise NotImplementedError

    def transition(self, command: bytes, state: bytes) -> Outcome:
        raise NotImplementedError


def output_len(decl: KernelDecl) -> int | None:
    """The v3 runtime's output buffer (``v3_output_len``)."""
    n = decl.max_output_bytes
    return n if 0 < n <= 65_536 else None


def judge(decl: KernelDecl, outcome: Outcome, prior: bytes, rejectable_session: bool) -> bool:
    """Whether the v3 runtime accepts a mirror outcome (``judge_outcome``)."""
    limit = output_len(decl)
    if limit is None or len(outcome.output) > limit:
        return False
    changed = len(prior) <= SNAPSHOT_CHECK_BYTES and outcome.state != prior
    if outcome.disposition == "continue":
        return True
    if outcome.disposition == "halt_before":
        return outcome.code != 0 and not changed
    if outcome.disposition == "halt_after":
        return outcome.code != 0
    if outcome.disposition == "reject":
        rejectable = rejectable_session and decl.rejects_input
        return rejectable and outcome.code != 0 and not outcome.output and not changed
    raise ValueError(f"unknown disposition {outcome.disposition!r}")


# --- the Rust side ------------------------------------------------------------------------------


def _hex(b: bytes) -> str:
    return b.hex() if b else "-"


def _unhex(w: str) -> bytes:
    return b"" if w == "-" else bytes.fromhex(w)


class RustKernels:
    """A running conformance server (``kernel_kit::conformance``)."""

    def __init__(self, binary: str | Path):
        self.proc = subprocess.Popen(
            [str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )

    def ask(self, line: str) -> str:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        answer = self.proc.stdout.readline()
        if not answer:
            raise RuntimeError("the conformance server exited")
        answer = answer.strip()
        if answer.startswith("error "):
            raise RuntimeError(f"conformance server: {answer} (request {line[:120]!r})")
        return answer

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)

    def __enter__(self) -> RustKernels:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _who(self, decl: KernelDecl) -> str:
        return f"{decl.id.hex()} {decl.semantic_version} {decl.abi_version}"

    def manifest(self, decl: KernelDecl) -> str:
        return self.ask(f"manifest {self._who(decl)}")

    def step(self, decl: KernelDecl, inputs: Sequence[bytes]) -> str:
        return self.ask(" ".join([f"step {self._who(decl)}", *(_hex(v) for v in inputs)]))

    def init(self, decl: KernelDecl, spans: Sequence[int]) -> str:
        return self.ask(f"init {self._who(decl)} {','.join(map(str, spans))}")

    def advance(self, decl: KernelDecl, rejectable: bool, spans: Sequence[int], state: bytes, command: bytes) -> str:
        return self.ask(
            f"advance {self._who(decl)} {int(rejectable)} {','.join(map(str, spans))} {_hex(state)} {_hex(command)}"
        )


# --- reports ------------------------------------------------------------------------------------


@dataclass
class Report:
    kernel: str
    cases: int = 0
    disagreements: list[str] = field(default_factory=list)
    #: Counts of each observed outcome kind, to show the cases reached
    #: refusals and edge paths (for example ``refused``, ``reject``).
    reached: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.disagreements

    def saw(self, kind: str) -> None:
        self.reached[kind] = self.reached.get(kind, 0) + 1

    def summary(self) -> str:
        reached = ", ".join(f"{k} {v}" for k, v in sorted(self.reached.items()))
        head = f"{self.kernel}: {self.cases} cases, {len(self.disagreements)} disagreements ({reached})"
        return "\n".join([head, *("  " + d for d in self.disagreements[:20])])


def _check_manifest(rust: RustKernels, decl: KernelDecl, stateful: bool, report: Report) -> bool:
    got = rust.manifest(decl)
    want = decl.manifest_line(stateful)
    if got != want:
        report.disagreements.append(f"manifest: rust {got!r}, mirror declares {want!r}")
        return False
    return True


# --- STEP cases ---------------------------------------------------------------------------------


def _fill(rng: random.Random, n: int, pattern: str) -> bytes:
    if pattern == "zero":
        return bytes(n)
    if pattern == "ff":
        return b"\xff" * n
    return rng.randbytes(n)


def _split(rng: random.Random, data: bytes, parts: int) -> list[bytes]:
    cuts = sorted(rng.randint(0, len(data)) for _ in range(parts - 1))
    bounds = [0, *cuts, len(data)]
    return [data[a:b] for a, b in zip(bounds, bounds[1:])]


def step_cases(decl: KernelDecl, seed: int = 0, random_cases: int = 64) -> list[list[bytes]]:
    """Inputs at every edge of the declared input limit (0, 1, max-1, max,
    max+1 total bytes), split into 1 to 3 spans (some empty), plus no spans,
    plus seeded random sizes up to 25% past the limit."""
    rng = random.Random(seed)
    m = decl.max_input_bytes
    sizes = sorted({0, 1, max(m - 1, 0), m, m + 1})
    cases: list[list[bytes]] = [[], [b""], [b"", b""]]
    for n in sizes:
        for pattern in ("zero", "ff", "random"):
            data = _fill(rng, n, pattern)
            for parts in (1, 2, 3):
                cases.append(_split(rng, data, parts))
    for _ in range(random_cases):
        n = rng.randint(0, m + m // 4 + 1)
        cases.append(_split(rng, _fill(rng, n, rng.choice(("zero", "ff", "random"))), rng.randint(1, 3)))
    return cases


def check_step(rust: RustKernels, mirror: StepMirror, cases: Iterable[list[bytes]] | None = None) -> Report:
    """Compare a STEP mirror with its Rust kernel: the manifest limits, then
    each case's output or refusal."""
    report = Report(f"{mirror.decl.name} v{mirror.decl.semantic_version}/{mirror.decl.abi_version} (STEP)")
    if not _check_manifest(rust, mirror.decl, False, report):
        return report
    for inputs in cases if cases is not None else step_cases(mirror.decl):
        report.cases += 1
        got = rust.step(mirror.decl, inputs)
        try:
            want = "output " + _hex(mirror(inputs)[0])
        except ValueError as e:
            want = "refused " + getattr(e, "kind", "ValueError")
        kind = got.split()[0]
        report.saw(kind)
        same = got == want if kind == "output" else want.startswith("refused") and kind == "refused"
        if not same:
            sizes = [len(v) for v in inputs]
            report.disagreements.append(f"inputs {sizes}: rust {got[:80]!r}, mirror {want[:80]!r}")
    return report


# --- stateful cases -----------------------------------------------------------------------------


def _commands(mirror: StatefulMirror, rng: random.Random) -> list[bytes]:
    m = mirror.decl.max_input_bytes
    out = [b"", b"\x00", b"\x01", b"\xff", bytes(m), b"\xff" * m, bytes(m + 1), *mirror.special_inputs]
    out += [rng.randbytes(rng.randint(1, max(m, 1))) for _ in range(4)]
    return out


def _states(mirror: StatefulMirror, initial: bytes, rng: random.Random) -> list[bytes]:
    n = sum(mirror.state_spans)
    return [initial, bytes(n), b"\xff" * n, b"\x7f" * n, *(rng.randbytes(n) for _ in range(3))]


def _rust_advance(answer: str) -> tuple[bool, Outcome | None, str]:
    words = answer.split()
    accepted = words[-1] == "accepted"
    if words[0] in ("failed", "not-stateful"):
        return accepted, None, words[0] if words[0] == "not-stateful" else "refused"
    kind, code, out, state = words[:4]
    raw = Outcome(b"" if out == "-" else _unhex(out), _unhex(state), kind, int(code))
    return accepted, raw, kind if accepted else "refused"


def _compare(report: Report, label: str, prior: bytes, got: tuple[bool, Outcome | None, str],
             want: Outcome | None, want_ok: bool) -> None:
    ok, raw, kind = got
    report.saw(kind)
    if ok != want_ok:
        report.disagreements.append(f"{label}: rust {'accepts' if ok else 'refuses'} {raw}, mirror {want}")
        return
    if not ok:
        return
    assert raw is not None and want is not None
    if (raw.disposition, raw.code, raw.state) != (want.disposition, want.code, want.state):
        report.disagreements.append(f"{label}: rust {raw}, mirror {want}")
    elif raw.disposition in ("continue", "halt_after") and raw.output != want.output:
        report.disagreements.append(f"{label}: output rust {raw.output.hex()}, mirror {want.output.hex()}")


def check_stateful(rust: RustKernels, mirror: StatefulMirror, seed: int = 0, walk: int = 64) -> Report:
    """Compare a stateful mirror with its Rust kernel: the manifest limits;
    initial state for the declared spans and for other splits; every
    generated command from the initial, zero, all-0xFF and random states at
    the state's full size, in plain and rejectable sessions; and a seeded walk
    of accepted transitions from the initial state."""
    decl = mirror.decl
    report = Report(f"{decl.name} v{decl.semantic_version}/{decl.abi_version} (stateful)")
    if not _check_manifest(rust, decl, True, report):
        return report
    rng = random.Random(seed)
    spans = mirror.state_spans
    total = sum(spans)
    initial = b""
    for split in (spans, (total,), (*spans[:-1], spans[-1] - 1, 1) if spans[-1] > 1 else (total,)):
        report.cases += 1
        got = rust.init(decl, split)
        try:
            state = mirror.initial_state(tuple(split))
            want = "state " + _hex(state) if len(state) == total else f"refused written {len(state)}"
        except ValueError as e:
            want = "refused kernel " + getattr(e, "kind", "ValueError")
        if split == spans and got.startswith("state "):
            initial = _unhex(got.split()[1])
        report.saw("init " + got.split()[0])
        if got != want and not (got.startswith("refused") and want.startswith("refused")):
            report.disagreements.append(f"init {list(split)}: rust {got!r}, mirror {want!r}")

    def one(state: bytes, command: bytes, rejectable: bool) -> tuple[bool, Outcome | None, str]:
        report.cases += 1
        got = _rust_advance(rust.advance(decl, rejectable, spans, state, command))
        try:
            want: Outcome | None = mirror.transition(command, state)
            want_ok = judge(decl, want, state, rejectable)
        except ValueError:
            want, want_ok = None, False
        label = f"state {state.hex()[:32]} command {command.hex()[:32] or '-'} rejectable {int(rejectable)}"
        _compare(report, label, state, got, want, want_ok)
        return got

    commands = _commands(mirror, rng)
    for state in _states(mirror, initial, rng):
        for command in commands:
            for rejectable in (False, True):
                one(state, command, rejectable)
    state = initial
    for _ in range(walk):
        ok, raw, _ = one(state, rng.choice(commands), rng.random() < 0.5)
        if ok and raw is not None and raw.disposition != "halt_before":
            state = raw.state
    return report


# --- command line -------------------------------------------------------------------------------


def _load(target: str):
    path = Path(target)
    if path.suffix == ".py" and path.exists():
        spec = importlib.util.spec_from_file_location(path.stem, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[path.stem] = module
        spec.loader.exec_module(module)
        return module
    return importlib.import_module(target)


def mirrors_in(module) -> tuple[list[StepMirror], list[StatefulMirror]]:
    """The STEP mirrors and stateful mirror instances a module defines."""
    steps = [v for v in vars(module).values() if isinstance(v, StepMirror)]
    states = [v for v in vars(module).values() if isinstance(v, StatefulMirror)]
    return steps, states


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dcg.kernel_kit")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check", help="compare mirrors with their Rust kernels")
    check.add_argument("--bin", required=True, help="the application's conformance server")
    check.add_argument("--seed", type=int, default=0)
    check.add_argument("modules", nargs="+", help="modules or .py files defining mirrors")
    args = parser.parse_args(argv)
    reports = []
    with RustKernels(args.bin) as rust:
        for target in args.modules:
            steps, states = mirrors_in(_load(target))
            reports += [check_step(rust, m, step_cases(m.decl, args.seed)) for m in steps]
            reports += [check_stateful(rust, m, args.seed) for m in states]
    for r in reports:
        print(r.summary())
    if not reports:
        print("no mirrors found")
        return 1
    return 0 if all(r.ok for r in reports) else 1


if __name__ == "__main__":
    # Run the imported module's main so mirror classes are the ones mirror
    # modules import (``-m`` would otherwise load this file twice).
    from dcg.kernel_kit import main as _main

    raise SystemExit(_main())
