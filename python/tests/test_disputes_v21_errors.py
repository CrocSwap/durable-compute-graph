"""The tag-227 error table names every code the program raises, and only those."""

from __future__ import annotations

import re
from pathlib import Path

from dcg.disputes_v21 import errors

SRC = Path(__file__).resolve().parents[2] / "crates" / "dcg-program" / "src"


def _raised() -> set[int]:
    assert "ProgramError::Custom(0x6600 + code)" in (SRC / "disputes_v21.rs").read_text()
    codes: set[int] = set()
    for name in ("disputes_v21.rs", "disputes_v21_lx.rs"):
        codes |= {int(n) for n in re.findall(r"\berr\((\d+)\)", (SRC / name).read_text())}
    return codes


def test_table_matches_the_program_source():
    assert set(errors.ERRORS) == _raised()


def test_names_are_unique_and_explained():
    assert len(errors.BY_NAME) == len(errors.ERRORS)
    for e in errors.ERRORS.values():
        assert e.meaning and e.fix and e.name.isidentifier()


def test_explain_reads_preflight_and_status_forms():
    assert errors.lookup(0x660D).name == "PhaseDeadlinePassed"
    assert "PhaseDeadlinePassed (0x660d)" in errors.explain(
        "tag 227 refused in preflight: Transaction simulation failed: custom program error: 0x660d")
    status = {"InstructionError": [1, {"Custom": 0x6600 + 9}]}
    assert errors.explain(status).startswith("NotDisputable (0x6609)")
    assert errors.explain({"InstructionError": [1, {"Custom": 7}]}) is None
    assert errors.explain("custom program error: 0x1771") is None
