"""ARM64 Stage 1b: exported register evidence through admission and the
program scope identity, and the ISA stack-register identity read from it
(design .census6/design_arm64_s1b.md r2, docs 25.86)."""

import json

import pytest

from synthetic import (
    AARCH64, REG, X64, X86_32, Arch, FunctionBuilder, _Provider, register_evidence,
)
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2._scope_envelope import open_configured_extraction
from tdo_v2._scope_raw import parse_raw_json
from tdo_v2._scope_results import ScopeConstructionReason, UnresolvedProgramScope
from tdo_v2.isa_identity import RegisterCoordinate, stack_register

_V2_ONLY = ("is_loaded_memory_space", "is_non_loaded_memory_space", "has_signed_offset")


class _Raw(_Provider):
    """A provider whose program candidate is given as JSON text (duplicate keys possible)."""

    text: str = ""

    def program_candidate(self):
        return parse_raw_json(self.text)


def _candidate(arch=X64, registers=None, revision=2):
    provider = _Provider([FunctionBuilder(arch=arch).ret()])
    candidate = provider._program_candidate()
    if revision == 1:
        del candidate["address_space_classification_revision"]
        for row in candidate["address_spaces"]:
            for name in _V2_ONLY:
                del row[name]
    if registers is not None:
        candidate["register_evidence"] = registers
    return candidate


def _program(arch=X64, *, registers=None, revision=2, text=None):
    provider = _Raw([FunctionBuilder(arch=arch).ret()])
    provider.text = text if text is not None else json.dumps(_candidate(arch, registers, revision))
    with open_configured_extraction(provider, _mint_orchestrator_capability()) as envelope:
        return envelope.program_result


def _digest(result):
    assert not isinstance(result, UnresolvedProgramScope), result
    return result.scope.digest


def _refused(result):
    assert isinstance(result, UnresolvedProgramScope), "admitted"
    return result.reason


def _table(*rows, revision=1):
    return {"revision": revision, "registers": [
        {"name": name, "space_id": space, "byte_offset": offset, "byte_size": size}
        for name, space, offset, size in rows]}


# -- identity -------------------------------------------------------------------

def test_absent_evidence_keeps_the_digest_and_present_evidence_changes_it():
    absent = _digest(_program())
    assert _digest(_program()) == absent
    assert _digest(_program(registers=register_evidence(X64))) != absent
    assert _digest(_program(registers=_table())) not in (absent, _digest(_program(registers=register_evidence(X64))))


def test_row_order_does_not_change_the_digest():
    table = register_evidence(AARCH64)
    shuffled = dict(table, registers=list(reversed(table["registers"])))
    assert _digest(_program(AARCH64, registers=table)) == _digest(_program(AARCH64, registers=shuffled))


@pytest.mark.parametrize("field,value", [("name", "RSQ"), ("byte_offset", 0x21), ("byte_size", 4)])
def test_every_field_of_a_row_is_in_the_digest(field, value):
    base = _table(("RSP", REG, 0x20, 8))
    changed = _table(("RSP", REG, 0x20, 8))
    changed["registers"][0][field] = value
    assert _digest(_program(registers=base)) != _digest(_program(registers=changed))


def test_overlapping_aliases_are_admitted():
    _digest(_program(AARCH64, registers=_table(("sp", REG, 8, 8), ("wsp", REG, 8, 4), ("x0", REG, 0x4000, 8),
                                               ("w0", REG, 0x4000, 4))))


# -- admission refusals ----------------------------------------------------------

INVALID = ScopeConstructionReason.INVALID_PROGRAM_REGISTER_EVIDENCE


@pytest.mark.parametrize("registers", [
    _table(("RSP", REG, 0x20, 8), revision=2),                        # unsupported revision
    _table(("RSP", REG, 0x20, 8), ("RSP", REG, 0x28, 8)),             # duplicate name
    _table(("RSP", 1, 0x20, 8)),                                       # not the register space (RAM)
    _table(("RSP", REG, 0x20, 0)),                                     # empty extent
    _table(("RSP", REG, (1 << 64) - 4, 8)),                            # overflowing extent
    {"revision": 1, "registers": [{"name": "RSP", "space_id": REG, "byte_offset": True, "byte_size": 8}]},
    {"revision": 1, "registers": [{"name": "RSP", "space_id": REG, "byte_offset": None, "byte_size": 8}]},
    {"revision": 1, "registers": [{"name": "RSP", "space_id": REG, "byte_offset": 0x20}]},   # missing field
    {"revision": 1},                                                   # missing rows
    None,                                                              # explicit null
    [],                                                                # not an object
])
def test_malformed_evidence_fails_admission(registers):
    candidate = _candidate()
    candidate["register_evidence"] = registers
    assert _refused(_program(text=json.dumps(candidate))) is INVALID


@pytest.mark.parametrize("flag", ["is_overlay_space", "is_memory_space", "is_unique_space", "is_constant_space"])
def test_a_register_space_with_conflicting_flags_is_not_a_register_space(flag):
    """The space must classify REGISTER (classify_address_space_v2), not
    merely carry the register flag (Astra)."""
    candidate = _candidate(registers=_table(("RSP", REG, 0x20, 8)))
    (row,) = [row for row in candidate["address_spaces"] if row["space_id"] == REG]
    row[flag] = True
    result = _program(text=json.dumps(candidate))
    assert isinstance(result, UnresolvedProgramScope)


def test_the_extent_counts_addressable_units():
    """An 8-bit register space with 2-byte units holds 0x200 bytes."""
    candidate = _candidate(registers=_table(("R", REG, 0x100, 8)))
    (row,) = [row for row in candidate["address_spaces"] if row["space_id"] == REG]
    row["address_size_bits"], row["addressable_unit_bytes"] = 8, 2
    _digest(_program(text=json.dumps(candidate)))
    candidate["register_evidence"] = _table(("R", REG, 0x1FC, 8))
    assert _refused(_program(text=json.dumps(candidate))) is INVALID


def test_evidence_needs_classification_revision_2():
    assert _digest(_program(revision=1))   # evidence-free revision 1 still admitted
    assert _refused(_program(revision=1, registers=register_evidence(X64))) is INVALID


def test_duplicate_fields_are_refused_at_every_level():
    text = json.dumps(_candidate(registers=_table(("RSP", REG, 0x20, 8))))
    record = '"register_evidence": '
    dup_record = text.replace(record, record + '{"revision": 1, "registers": []}, ' + record, 1)
    assert _refused(_program(text=dup_record)) is ScopeConstructionReason.PROGRAM_DUPLICATE_FIELD
    dup_revision = text.replace('"revision": 1', '"revision": 1, "revision": 1', 1)
    assert _refused(_program(text=dup_revision)) is INVALID
    dup_row = text.replace('"byte_size": 8', '"byte_size": 8, "byte_size": 8', 1)
    assert _refused(_program(text=dup_row)) is INVALID
    unknown_table = text.replace('"revision": 1', '"revision": 1, "extra": 1, "extra": 2', 1)
    assert _refused(_program(text=unknown_table)) is INVALID
    unknown_row = text.replace('"byte_size": 8', '"byte_size": 8, "extra": 1, "extra": 2', 1)
    assert _refused(_program(text=unknown_row)) is INVALID


# -- the ISA stack-register identity -----------------------------------------------

def _stack(arch, registers):
    result = _program(arch, registers=registers)
    assert not isinstance(result, UnresolvedProgramScope), result
    return stack_register(result.evidence)


@pytest.mark.parametrize("arch,expected", [
    (AARCH64, RegisterCoordinate("sp", REG, 0x8, 8)),
    (X64, RegisterCoordinate("RSP", REG, 0x20, 8)),
    (X86_32, RegisterCoordinate("ESP", REG, 0x10, 4)),
])
def test_the_stack_register_comes_from_the_exported_table(arch, expected):
    assert _stack(arch, register_evidence(arch)) == expected


def test_no_identity_without_evidence_or_for_an_unsupported_language():
    assert _stack(AARCH64, None) is None
    other = Arch("ARM:LE:32:v8", 4, 0x54, 0x5C)
    assert _stack(other, _table(("sp", REG, 0x54, 4))) is None


def test_no_identity_from_a_narrow_or_missing_row():
    assert _stack(AARCH64, _table(("sp", REG, 8, 4))) is None
    assert _stack(AARCH64, _table(("x0", REG, 0x4000, 8))) is None
