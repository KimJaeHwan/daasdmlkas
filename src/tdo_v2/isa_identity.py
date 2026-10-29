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
# the program counter as a p-code register (AArch64: indirect calls and
# returns go through it; x86's RIP / EIP)
_PROGRAM_COUNTERS = {
    ("AARCH64", "LE", "64"): ("pc", 8),
    ("x86", "LE", "64"): ("RIP", 8),
    ("x86", "LE", "32"): ("EIP", 4),
}
# the register a call instruction writes its continuation to, where the ISA
# has one (x86 pushes it to memory: none)
_LINK_REGISTERS = {
    ("AARCH64", "LE", "64"): ("x30", 8),   # AARCH64base.sinc: bl / blr write x30 = inst_start + 4
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
    return _named(evidence, _STACK_REGISTERS)


def link_register(evidence: VerifiedProgramSnapshotEvidence) -> RegisterCoordinate | None:
    """The link register (AArch64 x30) as the exported evidence places it;
    None where the ISA has none, or without exact evidence. Identity only."""
    return _named(evidence, _LINK_REGISTERS)


def program_counter(evidence: VerifiedProgramSnapshotEvidence) -> RegisterCoordinate | None:
    """The program counter register as the exported evidence places it."""
    return _named(evidence, _PROGRAM_COUNTERS)


def _named(evidence, names) -> RegisterCoordinate | None:
    require_exact(evidence, VerifiedProgramSnapshotEvidence, "program evidence")
    parts = tuple(evidence.translation_namespace.language_id.split(":"))
    wanted = names.get(parts[:3]) if len(parts) >= 4 else None
    table = evidence.register_evidence
    if wanted is None or table is None:
        return None
    name, size = wanted
    rows = [row for row in table.registers if row.name == name]
    if len(rows) != 1 or rows[0].byte_size != size:
        return None
    (row,) = rows
    return RegisterCoordinate(row.name, row.space_id, row.byte_offset, row.byte_size)
