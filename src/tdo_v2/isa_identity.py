"""ISA register identity from exported evidence (docs 25.86).

Which register of a supported language is its architectural stack register,
by the name its SLEIGH specification gives it -- an ISA fact, resolved against
the register table the exporter read from the language (never the compiler
spec's ``<stackpointer>``, never Ghidra's ``TYPE_SP`` roles, never the test
harness's tables). Identity only: nothing here says a call restores it, that
a function owns the memory it points to, or that any register is preserved.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import VerifiedProgramSnapshotEvidence, require_exact

# (processor, endianness, size) -> (SLEIGH name, full width in bytes)
_STACK_REGISTERS = {
    ("AARCH64", "LE", "64"): ("sp", 8),   # AARCH64instructions.sinc: define register ... [ pc sp ]
    ("x86", "LE", "64"): ("RSP", 8),
    ("x86", "LE", "32"): ("ESP", 4),
}


@dataclass(frozen=True, slots=True)
class RegisterCoordinate:
    """Where one named register lives (from the exported evidence)."""

    name: str
    space_id: int
    byte_offset: int
    byte_size: int


def stack_register(evidence: VerifiedProgramSnapshotEvidence) -> RegisterCoordinate | None:
    """The stack register of the program's language as its exported evidence
    places it; None for an unsupported language, no evidence, or no exact
    full-width row of that name."""
    require_exact(evidence, VerifiedProgramSnapshotEvidence, "program evidence")
    parts = tuple(evidence.translation_namespace.language_id.split(":"))
    wanted = _STACK_REGISTERS.get(parts[:3]) if len(parts) >= 4 else None
    table = evidence.register_evidence
    if wanted is None or table is None:
        return None
    name, size = wanted
    rows = [row for row in table.registers if row.name == name]
    if len(rows) != 1 or rows[0].byte_size != size:
        return None
    (row,) = rows
    return RegisterCoordinate(row.name, row.space_id, row.byte_offset, row.byte_size)
