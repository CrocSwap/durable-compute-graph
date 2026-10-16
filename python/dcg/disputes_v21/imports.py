"""Imported inputs for v2.1 templates (pipelines slice 1, design
``docs/design/mixed-mode-pipelines-v1.md`` §3.1; program feature
``pipelines-v1``).

A template's create data may end with an import table: ``"DIM0" count:u8
zero(3)`` then ``count`` 104-byte ImportSpec records, external ids strictly
increasing. The template id hashes the whole create data, the table included.
An import's run takes version-1 init and is a version-2 run; ``IMPORT`` (tag
227 sub 29) verifies one imported input against a final result."""
from __future__ import annotations

import struct
from dataclasses import dataclass

from dcg import result as R

IMPORT_TAIL_MAGIC = b"DIM0"
IMPORT_SPEC_MAGIC = b"DIM1"
IMPORT_SPEC_BYTES = 104
MAX_IMPORTS = 16
SOURCE_RESULT = 2
SUB_IMPORT = 29


@dataclass(frozen=True)
class ImportSpec:
    external_id: int
    scheme: int  # R.SCHEME_OUT_TREE_V21 (one output) or R.SCHEME_STATE_TREE_V1 (the whole state)
    out_index: int
    requirements: R.Requirements
    host: bytes  # the program the source must belong to

    def encode(self) -> bytes:
        if self.scheme == R.SCHEME_STATE_TREE_V1 and self.out_index:
            raise ValueError("a state import takes the whole state (out_index 0)")
        if self.scheme not in (R.SCHEME_OUT_TREE_V21, R.SCHEME_STATE_TREE_V1) or len(self.host) != 32:
            raise ValueError("unsupported import")
        # The program never verifies requirements that do not name the
        # computation (a run import its template or run, a state import its
        # kernel) or that state another mode.
        q = self.requirements
        if self.scheme == R.SCHEME_STATE_TREE_V1:
            named, mode = q.kernel is not None, R.MODE_CONSENSUS
        else:
            named, mode = q.template_id is not None or q.run_id is not None, R.MODE_OPTIMISTIC
        if not named or q.mode not in (None, mode):
            raise ValueError("requirements must name the computation and match the scheme's mode")
        return (IMPORT_SPEC_MAGIC + struct.pack("<IBB", self.external_id, SOURCE_RESULT, self.scheme) + bytes(6)
                + struct.pack("<Q", self.out_index) + self.requirements.digest() + bytes(self.host) + bytes(16))


def import_tail(specs: list[ImportSpec]) -> bytes:
    """The import table appended to a template's create data."""
    ids = [s.external_id for s in specs]
    if not 1 <= len(specs) <= MAX_IMPORTS or ids != sorted(set(ids)):
        raise ValueError("1..16 imports with strictly increasing external ids")
    return IMPORT_TAIL_MAGIC + bytes([len(specs)]) + bytes(3) + b"".join(s.encode() for s in specs)


def import_data(external_id: int, requirements: R.Requirements, value_ref: bytes | None = None,
                path: list[bytes] | None = None) -> bytes:
    """IMPORT (sub 29) data after the tag and sub bytes: the output's value
    reference and path for an out-tree import, nothing for a state import."""
    drq = requirements.encode()
    out = struct.pack("<IH", external_id, len(drq)) + drq
    if value_ref is not None:
        out += bytes(value_ref) + bytes([len(path or [])]) + b"".join(path or [])
    return out
