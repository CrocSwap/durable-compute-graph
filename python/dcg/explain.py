"""`explain()` for both modes (alpha plan E8): what a template or a session
guarantees, what it costs, and what it does not cover, in plain language.

    print(explain.template(rpc_url, template, spec=plan))   # optimistic (v2.1)
    print(await session.explain(decl=MANIFEST))            # consensus (sessions)
    dcg explain template --rpc URL --template T [--plan FILE.py:NAME]

A template is read from chain. With its plan, the plan is checked against
the template's spec root and plan id, and the kernels and the dispute path
are described. Windows are checked against the largest witness a dispute
must stage, and against the time a remote watcher needs (owner, 2026-10-05:
the program keeps its 750-slot minimums; `explain` flags windows that are
tight).
"""

from __future__ import annotations

import base64
import math
import struct
from dataclasses import dataclass, field
from typing import Callable

from solders.pubkey import Pubkey

LAMPORTS = 1_000_000_000
#: Template account layout (disputes_v21.rs `template`).
T_DEPTH, T_KIND, T_STEPS, T_OUTPUTS, T_CHALLENGE, T_PHASE = 4, 5, 8, 16, 24, 32
T_EXEC_BOND, T_CHAL_BOND, T_SPEC_ROOT, T_ID, T_SLASHER, T_PLAN_ID = 40, 48, 64, 96, 128, 136
T_RETIRED, T_FIXED, T_BLOCKS, T_LX = 134, 168, 176, 280
#: The program's minimum phase and challenge windows (admission, §5.3).
MIN_WINDOW = 750
#: A remote watcher's slowest tick, measured on testnet from a Mac at ~350 ms
#: per RPC call (2026-10-05, docs/services.md).
REMOTE_TICK_S = 33.0
CLAIMS = ("EDGE", "STATE", "STEP", "GATE", "SHAPE", "OUT")


@dataclass
class Explanation:
    title: str
    sections: list[tuple[str, list[str]]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def add(self, heading: str, *lines: str) -> None:
        self.sections.append((heading, [line for line in lines if line]))

    def __str__(self) -> str:
        out = [self.title]
        for heading, lines in self.sections:
            out.append(f"{heading}:")
            out += [f"  {line}" for line in lines]
        if self.warnings:
            out.append("warnings:")
            out += [f"  ! {w}" for w in self.warnings]
        return "\n".join(out)


def _u16(d: bytes, at: int) -> int:
    return struct.unpack_from("<H", d, at)[0]


def _u32(d: bytes, at: int) -> int:
    return struct.unpack_from("<I", d, at)[0]


def _u64(d: bytes, at: int) -> int:
    return struct.unpack_from("<Q", d, at)[0]


def _name(kernel_id: bytes) -> str:
    raw = bytes(kernel_id).rstrip(b"\x00")
    try:
        return raw.decode()
    except UnicodeDecodeError:
        return raw.hex()


def _fogo(lamports: int) -> str:
    return f"{lamports / LAMPORTS:g} FOGO ({lamports:,} lamports)"


def _seconds(slots: int, slot_ms: float) -> str:
    s = slots * slot_ms / 1000
    return f"{slots:,} slots (~{s:.0f} s at {slot_ms:g} ms/slot)"


def _read(rpc: Callable[[str, list], object], key: str) -> bytes | None:
    value = rpc("getAccountInfo", [key, {"encoding": "base64", "commitment": "confirmed"}])["value"]
    return None if value is None else base64.b64decode(value["data"][0])


def template(rpc_url: str | None, template_key: Pubkey | str, *, spec=None, plan_id: bytes | None = None,
             slot_ms: float = 40.0, watcher_tick_s: float = REMOTE_TICK_S,
             rpc: Callable[[str, list], object] | None = None, data: bytes | None = None) -> Explanation:
    """Explain a v2.1 template from its account (`data`, or read with `rpc`),
    and from its plan (`spec`) when given."""
    from .runtime import _rpc_at

    if data is None:
        data = _read(rpc or _rpc_at(rpc_url), str(template_key))
    if data is None or data[:4] != b"D21T":
        raise ValueError(f"{template_key} is not a v2.1 template")
    lx = data[T_KIND] == 1
    tracked = len(data) >= 40 and data[len(data) - 40:len(data) - 36] == b"D21O"
    t = {
        "depth": data[T_DEPTH], "total_steps": _u64(data, T_STEPS), "total_outputs": _u64(data, T_OUTPUTS),
        "challenge_window": _u64(data, T_CHALLENGE), "phase_window": _u64(data, T_PHASE),
        "executor_bond": _u64(data, T_EXEC_BOND), "challenger_bond": _u64(data, T_CHAL_BOND),
        "spec_root": bytes(data[T_SPEC_ROOT:T_SPEC_ROOT + 32]), "plan_id": bytes(data[T_PLAN_ID:T_PLAN_ID + 32]),
        "slasher_bps": _u16(data, T_SLASHER), "blocks": data[T_FIXED],
        "retired": bool(data[T_RETIRED]) if tracked else False,
        "active_runs": _u32(data, len(data) - 4) if tracked else None,
    }
    e = Explanation(f"template {template_key} ({'LX1 checkpointed machine' if lx else 'v2.1 plan'})", data=t)
    state = "retired (no new runs)" if t["retired"] else "open for runs"
    e.add("status", state + (f", {t['active_runs']} live run(s)" if t["active_runs"] is not None else ""),
          "guarantee: optimistic. A wrong commitment is refuted only if a watcher challenges it inside the "
          "challenge window; the program then replays the disputed step.")

    if lx:
        _explain_lx(e, data)
    else:
        _explain_plan(e, t, spec, plan_id, slot_ms, watcher_tick_s)

    e.add("windows",
          f"challenge: {_seconds(t['challenge_window'], slot_ms)} after commit",
          f"each phase: {_seconds(t['phase_window'], slot_ms)}; a party that misses a phase loses that dispute")
    chal_s = t["challenge_window"] * slot_ms / 1000
    if chal_s < 2 * watcher_tick_s:
        e.warnings.append(
            f"the challenge window (~{chal_s:.0f} s) is shorter than twice a remote watcher's slowest tick "
            f"(~{watcher_tick_s:.0f} s measured on testnet): a lie may finalize before a remote watcher checks it")
    e.add("bonds",
          f"executor: {_fogo(t['executor_bond'])}; challenger: {_fogo(t['challenger_bond'])} per dispute",
          f"a winning challenger gets {t['slasher_bps'] / 100:g}% of the executor bond; the rest goes to the run's payer")
    e.add("limits (alpha)",
          "the plan behind the spec root is trusted: check it off chain (pass the plan to explain)",
          "inputs are committed as digests only: a watcher can check a run only if the application makes "
          "its inputs available",
          "application kernels resolve against the program image that is live when a dispute is ruled",
          "the LX1 watchtower is not in v1: LX1 runs are checked only by watchers you run" if lx else "")
    return e


def _explain_plan(e: Explanation, t: dict, spec, plan_id: bytes | None, slot_ms: float, watcher_tick_s: float) -> None:
    from .disputes_v21 import trees
    from .disputes_v21 import wire as W

    e.add("plan", f"{t['total_steps']} step(s) in {t['blocks'] or 1} block(s), {t['total_outputs']} output(s)",
          f"spec root {t['spec_root'].hex()[:16]}…, plan id {t['plan_id'].hex()[:16]}…")
    if spec is None:
        e.warnings.append("no plan given: the kernels, the dispute depth and the largest witness are not checked")
        return
    matches = spec.root == t["spec_root"] and (plan_id is None or plan_id == t["plan_id"]) \
        and spec.total_steps == t["total_steps"] and spec.total_outputs == t["total_outputs"]
    if not matches:
        e.warnings.append("the given plan does NOT match this template's spec root or counts")
        return
    e.add("plan check", "the given plan matches the template's spec root and counts")
    _explain_kernels(e, spec)
    height = spec.address_height
    out_height = trees.height_for(spec.total_outputs)
    rounds = math.ceil(height / max(t["depth"], 1)) if height else 0
    out_rounds = math.ceil(out_height / max(t["depth"], 1)) if out_height else 0
    e.add("dispute path",
          f"descent over the step tree (height {height}) or the output tree (height {out_height}), "
          f"{t['depth']} level(s) per round: at most {rounds} / {out_rounds} round(s), then a claim",
          f"claims: {', '.join(CLAIMS)}; the program replays at most one step per claim",
          f"a dispute takes at most {2 * max(rounds, out_rounds) + 2} phases")
    witness = W.largest_step_witness(spec)
    need = W.phase_window_for(witness, slot_ms=slot_ms)
    e.add("staging", f"largest STEP witness: {witness:,} bytes; needs a phase window of at least {need:,} slots "
                     f"at {slot_ms:g} ms/slot (upload at the measured testnet rate)")
    if t["phase_window"] < need:
        e.warnings.append(f"the phase window ({t['phase_window']:,} slots) is too short to stage the largest "
                          f"witness ({need:,} needed)")
    phase_s = t["phase_window"] * slot_ms / 1000
    if phase_s < 2 * watcher_tick_s:
        e.warnings.append(
            f"the phase window (~{phase_s:.0f} s) is under twice a remote watcher's slowest tick "
            f"(~{watcher_tick_s:.0f} s): watchers and executors should run close to their RPC node")
    if any(spec.step_spec(k)[120] == 2 for k in range(min(spec.total_steps, 4096))):
        e.warnings.append("the plan has LOG-state steps: LOG is not supported in the alpha, and a lie there is ruled moot, not convicted; refuse this template")


def _explain_kernels(e: Explanation, spec) -> None:
    from .disputes_v21 import reductions
    from .disputes_v21 import run as R
    from .disputes_v21 import spec as S
    from .kernel_kit import STEP_REGISTRY

    seen: dict[tuple[bytes, int, int], int] = {}
    for k in range(spec.total_steps):
        d = S.decode_step_spec(spec.step_spec(k))
        key = (bytes(d["kernel_id"]), d["semantic_version"], d["abi_version"])
        seen[key] = seen.get(key, 0) + 1
    lines = []
    for (kid, sv, abi), n in seen.items():
        name = f"{_name(kid)} v{sv}/{abi} ({n} step{'s' if n > 1 else ''})"
        if reductions.lookup(kid) is not None:
            lines.append(f"{name}: built-in reduction, replayed by the program")
        elif R.replay_known(kid):
            lines.append(f"{name}: built-in kernel, replayed by the program")
        else:
            mirror = STEP_REGISTRY.get((kid, sv, abi))
            limits = (f"; mirror declares ≤{mirror.decl.max_input_bytes:,} B in, ≤{mirror.decl.max_output_bytes:,} B "
                      f"out, ≤{mirror.decl.max_compute_units:,} CU") if mirror else "; no Python mirror registered"
            lines.append(f"{name}: application kernel, resolved by id and versions from the program image's "
                         f"manifest (must advertise STEP mode){limits}")
    e.add("kernels", *lines)


def _explain_lx(e: Explanation, data: bytes) -> None:
    tail = data[T_LX:T_LX + 44]
    if tail[:4] != b"DLX1":
        e.warnings.append("the LX1 tail is missing or malformed")
        return
    kernel, sv, abi = tail[4:20], _u16(tail, 20), _u16(tail, 22)
    arity, k_min, k_max, max_positions = tail[24], _u32(tail, 28), _u32(tail, 32), _u64(tail, 36)
    e.add("machine", f"kernel {_name(kernel)} v{sv}/{abi} (an LX1 machine from the program image's manifest)",
          f"checkpoint every k positions, k in [{k_min}, {k_max}]; at most {max_positions:,} positions",
          f"constants root {bytes(data[T_SPEC_ROOT:T_SPEC_ROOT + 32]).hex()[:16]}…")
    e.add("dispute path",
          f"open a checkpoint pair, then bisect with arity {arity} to one transition, which the program replays "
          "from an opening",
          f"rounds ≈ log_{arity}(transitions between checkpoints); an OUTPUT claim checks the final outputs directly")


def session_text(info, kernel, decl=None, runtime: str | None = None, max_steps: int | None = None) -> str:
    """A session's guarantee, kernel and bounds, then its live state
    (`SessionInfo.explain`)."""
    lines = ["guarantee: consensus. The program executes every input itself, in order; there are no "
             "disputes, bonds or challenge windows"]
    if runtime:
        lines.append(f"program runtime: {runtime}")
    name = _name(kernel.id)
    lines.append(f"kernel: {name} v{kernel.semantic_version}/{kernel.abi_version}, mode v{kernel.mode_version}"
                 + (", may reject inputs" if kernel.rejects_input else ""))
    lines.append(f"input: {kernel.input_width} byte(s) per step; state: {sum(kernel.state_span_lengths):,} bytes "
                 f"in {len(kernel.state_span_lengths)} span(s)")
    if decl is not None:
        per_tx = decl.max_compute_units * (max_steps or 1)
        lines.append(f"per step: at most {decl.max_compute_units:,} CU; "
                     f"{max_steps or 1} step(s) per transaction (≤ {per_tx:,} CU of the 1,400,000 limit)")
    lines.append(info.explain())
    return "\n".join(lines)
