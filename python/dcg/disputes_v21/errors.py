"""Names and meanings of the tag-227 (v2.1 disputes) error codes.

The program refuses with ``Custom(0x6600 + n)`` (``err(n)`` in
``disputes_v21.rs`` and ``disputes_v21_lx.rs``). Many codes are raised at
several places; the meaning below covers them all, and ``fix`` says what a
caller usually got wrong. ``tests/test_disputes_v21_errors.py`` checks this
table against every code the program source raises.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

BASE = 0x6600


@dataclass(frozen=True)
class DisputeError:
    code: int
    name: str
    meaning: str
    fix: str

    @property
    def custom(self) -> int:
        """The on-chain ``Custom`` value."""
        return BASE + self.code

    def __str__(self) -> str:
        return f"{self.name} (0x{self.custom:04x}): {self.meaning}. {self.fix}"


_TABLE: list[tuple[int, str, str, str]] = [
    (1, "MalformedData", "the instruction or an account is too short to read a field",
     "Check the instruction encoding and that the right accounts are passed."),
    (2, "WrongAddress", "an account is not the address its seeds derive, or is not owned by the program",
     "Derive the PDA with the client helpers; pass the template, run, dispute or buffer it expects."),
    (3, "AccountExists", "the account to create is not an empty system account",
     "Use a fresh run id, or close the old account first."),
    (4, "BadTemplate", "the template account is malformed, untracked, or has an invalid block count",
     "Pass a v2.1 template created by this program."),
    (5, "BadRun", "the account is not a v2.1 run (or receipt) of this template",
     "Pass the run created from this template."),
    (6, "TemplateRefused", "template admission failed: a window, bond or slasher share below its floor, "
     "nonzero reserved bytes, a non-canonical block list, or blocks that do not cover the declared steps",
     "Build the template with the client encoder; see optimistic-descent-v2.1.md §5.3."),
    (7, "CommitRefused", "the run is not open, its commit deadline passed, or the commitment does not match "
     "the template (spec root, steps, outputs, run id or LX checkpoints)",
     "Commit before the deadline, with the run root computed for this template and run."),
    (8, "Overflow", "arithmetic overflow, or a length that does not fit",
     "Usually malformed input; check counts and lengths."),
    (9, "NotDisputable", "the run is not committed, or its challenge window has closed",
     "Open disputes (and stage for them) only while the challenge window is open."),
    (10, "WrongDisputeKind", "the instruction does not apply to this dispute kind or template",
     "Descent steps act on STEP/OUT descents; LX steps need an LX1 template."),
    (11, "BadDispute", "the account is not a dispute of this run",
     "Pass the dispute PDA of this run."),
    (12, "WrongPhase", "the dispute is not in the phase this instruction acts in",
     "Read the dispute's phase and send the step it expects."),
    (13, "PhaseDeadlinePassed", "the phase deadline passed",
     "The other side may now claim a timeout; act sooner, or use timeout yourself."),
    (14, "BadReveal", "the revealed nodes do not fold to the disputed node",
     "Reveal the committed tree's nodes at the dispute's position and depth."),
    (15, "BadPick", "the picked child index is out of range or not a pickable node",
     "Pick an index below the reveal's width that addresses a real step or output."),
    (16, "BadLeafLists", "list-input element references are malformed, unordered, or exceed the limits",
     "Encode list inputs with the client (strictly increasing input index, 1 to MAX_LIST_ELEMENTS refs)."),
    (17, "BadSpecRecord", "a spec record does not open under the template's spec root, or is not the "
     "record kind the claim needs",
     "Open the spec record the step or output names, with its proof."),
    (18, "BadStepOpening", "the step leaf does not open under the committed step root",
     "Open the leaf at the disputed position with its path from the run root."),
    (19, "BadProducer", "a producer reference names no step, block or port the template has",
     "Check the plan's producer kinds and ordinals."),
    (20, "BadStepInputs", "the step's input count or list inputs do not match its leaf and spec",
     "Open every input the spec names, list inputs with their element references."),
    (22, "WrongSigner", "the signer is not this dispute's challenger or this run's executor",
     "Sign with the key recorded on the dispute or run."),
    (23, "TimeoutTooEarly", "the dispute is already ruled, or its phase deadline has not passed",
     "Wait for the deadline before claiming a timeout."),
    (24, "NotFinalizable", "the run is not committed, its challenge window is still open, or disputes are open",
     "Finalize after the window, once every dispute is ruled and closed."),
    (25, "AlreadyRuled", "the dispute is already ruled, or the run is no longer committed or refuted",
     "Nothing to do; read the ruling."),
    (26, "RulingOutOfOrder", "rulings advance the run in dispute order; an earlier dispute is still open",
     "Advance the earliest open dispute first."),
    (27, "NotMoot", "the dispute cannot be ruled moot: it is ruled, not after the run's lowest win, "
     "or the signer is not its challenger",
     "Only a dispute opened after the lowest challenger win is moot."),
    (28, "NotPayable", "the pot is paid only to the winning challenger of a refuted run, with its payer",
     "Pay from the dispute the challenger won, passing the run's payer."),
    (29, "BadStaging", "a staging buffer is malformed, the wrong role or dispute, or a write is out of range",
     "Create and write staging buffers with the client; stay within CREATE_STAGE and the buffer's size."),
    (30, "BadCache", "the reveal cache does not answer this dispute node",
     "Use the cache derived for this run, kind, level and position."),
    (31, "BadRunInit", "external references are not in strictly increasing id order, or the payer is the executor",
     "Sort external refs by id; use a payer different from the executor."),
    (32, "BadChunkProof", "a chunk does not open under its chunked input's root",
     "Open the chunk with its path in the chunk tree."),
    (33, "BadGateValue", "the gate's value does not match its producer's committed output",
     "Open the gate value from the producer leaf."),
    (34, "BadConstant", "a constant opening is not a committed constant record with this id",
     "Open the constant's DCN1 record from the spec tree."),
    (35, "NotWritable", "the template (or another account the instruction updates) is not writable",
     "Pass the template as writable."),
    (36, "CannotCloseDispute", "the dispute is not closable yet, or the challenger or executor account is wrong",
     "Close after the ruling (and, for the best refutation, after the pot is paid)."),
    (37, "NotAllowedNow", "the account's state does not allow this now: a retired or untracked template, a "
     "template with live runs, a run not yet settled, or a dispute already opened or ruled",
     "Read the template, run or dispute state; follow the lifecycle order."),
    (38, "CacheNotClosable", "the cache's run is not settled, has open disputes, or records no executor",
     "Close caches after the run settles."),
    (40, "RunPredatesUpgrade", "the run's layout predates this image's wait trailer",
     "Drain old runs before an in-place upgrade."),
    (42, "BadLxParams", "the LX parameters do not match the run's digest, or the machine refuses them",
     "Pass the parameters the run was committed with."),
    (43, "NotLxKernel", "the kernel is not an LX1 machine, or it declares REJECTS_INPUT",
     "Bind an LX1 kernel that does not reject inputs."),
    (44, "BadCheckpointPair", "the checkpoint pair does not open under the committed checkpoint root, "
     "or spans an empty interval",
     "Open two adjacent committed checkpoints that bracket the divergence."),
    (45, "BadMidpoints", "the midpoint count does not match the interval and arity",
     "Send one 32-byte root per midpoint coordinate."),
    (46, "BadOpening", "an LX opening is malformed",
     "Encode openings with the LX client."),
    (47, "LxCoordinate", "an LX opening addresses the wrong coordinate",
     "Open the coordinates the machine asks for."),
    (48, "LxCoverage", "the LX opening does not cover every read the step makes",
     "Open every slot the step reads."),
    (49, "LxProof", "an LX opening's proof does not verify",
     "Open from the committed state with valid paths."),
    (50, "BadConstantOpening", "too many constant reads, or a chunk path too long",
     "Stay within the step's read and path limits."),
]

ERRORS: dict[int, DisputeError] = {c: DisputeError(c, n, m, f) for c, n, m, f in _TABLE}
BY_NAME: dict[str, DisputeError] = {e.name: e for e in ERRORS.values()}

_HEX = re.compile(r"custom program error: 0x([0-9a-fA-F]+)")
_DEC = re.compile(r"['\"]Custom['\"]:\s*(\d+)")


def lookup(custom: int) -> DisputeError | None:
    """The error for an on-chain ``Custom`` value, or None if it is not a
    tag-227 code."""
    return ERRORS.get(custom - BASE)


def explain(error: object) -> str | None:
    """Name the first tag-227 code in an RPC error or status (preflight text
    ``custom program error: 0x660d`` or ``{'Custom': 26125}``)."""
    text = str(error)
    for m in _HEX.finditer(text):
        if (e := lookup(int(m.group(1), 16))) is not None:
            return str(e)
    for m in _DEC.finditer(text):
        if (e := lookup(int(m.group(1)))) is not None:
            return str(e)
    return None
