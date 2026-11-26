"""ISA register identity from exported evidence (docs 25.86).

Which register of a supported language is its architectural stack register,
by the name its SLEIGH specification gives it -- an ISA fact, resolved against
the register table the exporter read from the language (never the compiler
spec's ``<stackpointer>``, never Ghidra's ``TYPE_SP`` roles, never the test
harness's tables). Identity only: nothing here says a call restores it, that
a function owns the memory it points to, or that any register is preserved.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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


# (PE-a1) the x86 direction flag as SLEIGH names it (ia.sinc: DF, one byte)
_DIRECTION_FLAGS = {
    ("x86", "LE", "64"): ("DF", 1),
    ("x86", "LE", "32"): ("DF", 1),
}


def _language_parts(evidence) -> tuple | None:
    """(PE-a1, Astra r6 P3) The one language-id rule of both DF identity paths
    and ``_named``: a full id (four parts or more) -> its first three parts."""
    parts = tuple(evidence.translation_namespace.language_id.split(":"))
    return parts[:3] if len(parts) >= 4 else None


def x86_language(evidence) -> bool:
    """(PE-a1) An x86 language by ``_language_parts``."""
    return _language_parts(evidence) in _DIRECTION_FLAGS


_TABLE_FLAGS: dict = {}   # id(evidence) -> (evidence, its table DF row) -- one lookup per program


def direction_flag(evidence: VerifiedProgramSnapshotEvidence) -> RegisterCoordinate | None:
    """The x86 direction flag as the exported register evidence places it;
    None for another language or without exact evidence (no certificate).
    Looked up once per program snapshot (Astra r6 P2)."""
    held = _TABLE_FLAGS.get(id(evidence))
    if held is not None and held[0] is evidence:
        return held[1]
    if len(_TABLE_FLAGS) > 64:
        _TABLE_FLAGS.clear()
    found = _named(evidence, _DIRECTION_FLAGS)
    _TABLE_FLAGS[id(evidence)] = (evidence, found)
    return found


# (Astra r6 P1-2) a certificate is issued only by ``inferred_direction_flag``:
# its seal is a keyed digest of its fields with a key private to this process,
# so neither direct construction nor ``dataclasses.replace`` (say, adding an
# observation the unanimity never covered) yields a certificate
_SEAL_KEY = __import__("os").urandom(32)


def _seal_of(program, flag, observations) -> bytes:
    import hashlib
    import hmac

    text = repr((program, flag, tuple(sorted(observations)))).encode("utf-8")
    return hmac.new(_SEAL_KEY, text, hashlib.sha256).digest()


@dataclass(frozen=True, slots=True)
class InferredDirectionFlag:
    """(PE-a1) The program-wide DF coordinate, bound to the program snapshot
    it was inferred from (``program``: its program scope id) and to the
    observations its unanimity covered (``observations``: their digests; the
    certificate is used only for one of them, ``normalize._direction_flag_of``).
    Issued only by ``inferred_direction_flag`` (``seal``)."""

    program: object
    flag: RegisterCoordinate
    observations: frozenset
    seal: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.observations) is not frozenset or type(self.seal) is not bytes \
                or not __import__("hmac").compare_digest(self.seal, _seal_of(self.program, self.flag,
                                                                             self.observations)):
            raise ValueError("an inferred direction flag is issued only by inferred_direction_flag")


def _issue(program, flag, observations) -> InferredDirectionFlag:
    """(module-private) the one issuer -- tests reach the consumer guards with it."""
    observations = frozenset(observations)
    return InferredDirectionFlag(program, flag, observations, _seal_of(program, flag, observations))


_INFERRED: dict = {}   # (program, digests) -> result: one scan per observation set (Astra r6 P2)


def _digest_of(unit):
    """The observation digest the unit's function scope already validated
    (``ScopedFunctionUnit``: constructed scopes bind it, refusals retain it)."""
    function = unit.scopes.function
    return getattr(function, "observation_digest", None) or getattr(function, "validated_observation_digest", None)


def inferred_direction_flag(units) -> InferredDirectionFlag | None:
    """(PE-a1; owner 2026-11-25, Astra / Fable r2 P2-2) Without an exported
    register table: the one-byte direction operand every recognised ``rep
    movs`` / ``rep stos`` row of the program names (``rep_strings.recognize``:
    the exact string-instruction lifting), when the language is x86 and that
    coordinate is unanimous across every observed body (cut ones included).
    The identification rests on the base premise decoder-matches-cpu (P-0):
    in that lifting the byte deciding the direction is DF by ISA. A program
    with a register table, another language, no rep row or disagreeing rows:
    None (the table rule, or no certificate). ``units``: every retained
    observation of ONE program snapshot -- admitted, cut and refused-at-
    admission bodies alike (Astra r4 P1-1); the caller passes every
    observation of the snapshot it holds. Units of several snapshots, or a
    unit whose program scope was refused: None. The result is bound to that
    snapshot and to the observations it covered, and is the only issuer of a
    certificate."""
    from ._scope_results import ConstructedProgramScope
    from .rep_strings import recognize

    supplied = list(units)
    if not supplied or any(type(unit.scopes.program) is not ConstructedProgramScope for unit in supplied):
        return None
    # (Astra r5 P2) every supplied unit's snapshot -- an observation-free
    # refusal of another snapshot included -- before any observation is read
    program = supplied[0].scopes.program.scope
    if any(unit.scopes.program.scope != program for unit in supplied):
        return None
    observations = {}
    for unit in supplied:   # (each observation once: a unit may be passed twice)
        if unit.observation is not None:
            digest = _digest_of(unit)
            if digest is None:
                return None
            observations.setdefault(digest, unit.observation)
    if not observations:
        return None
    evidence = supplied[0].scopes.program.evidence
    if not x86_language(evidence) or evidence.register_evidence is not None:
        return None
    key = (program, frozenset(observations))
    if key in _INFERRED:
        return _INFERRED[key]
    if len(_INFERRED) > 64:
        _INFERRED.clear()
    found = set()
    for observation in observations.values():
        for instruction in observation.instructions:
            site = recognize(instruction)
            if site is not None:
                operand = site.direction
                found.add((operand.coordinate.space_id, operand.coordinate.byte_offset, operand.byte_size))
    result = None
    if len(found) == 1:
        ((space_id, offset, size),) = found
        if size == 1:
            result = _issue(program, RegisterCoordinate("DF", space_id, offset, size), observations)
    _INFERRED[key] = result
    return result


def is_direction_flag(varnode, flag: RegisterCoordinate | None) -> bool:
    """``varnode`` is exactly the direction flag (``direction_flag``)."""
    return flag is not None and varnode.byte_size == flag.byte_size \
        and (varnode.coordinate.space_id, varnode.coordinate.byte_offset) == (flag.space_id, flag.byte_offset)


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
    parts = _language_parts(evidence)
    wanted = names.get(parts) if parts is not None else None
    table = evidence.register_evidence
    if wanted is None or table is None:
        return None
    name, size = wanted
    rows = [row for row in table.registers if row.name == name]
    if len(rows) != 1 or rows[0].byte_size != size:
        return None
    (row,) = rows
    return RegisterCoordinate(row.name, row.space_id, row.byte_offset, row.byte_size)
