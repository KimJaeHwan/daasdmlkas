"""A point certificate cannot authorize a whole address object's accesses."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import RDX, RDI, FunctionBuilder, const, reg, store
from test_import_slot_pointers import _analyze, _function
from tdo_v2.effects import EffectKind, ObservedEffect, UnresolvedMemoryAccess
from tdo_v2.forward import probe
from tdo_v2.may_alias import _bounded_nonstack_objects
from tdo_v2.model import ResolvedStorage
from tdo_v2.resource_limits import AnalysisBudgetExceeded
from tdo_v2.relative_memory import _AddressExpression, _Projector
from tdo_v2.span_geometry import ByteSpan


@pytest.mark.parametrize("origin", ("fresh", "nonstack"))
@pytest.mark.parametrize("atoms,offset,image,expected", (
    (((1, 1),), 0, 0, True),
    (((1, 1),), 1, 0, False),
    (((1, 1),), -1, 0, False),
    (((1, 1),), 0, 1, False),
    (((1, 1),), 0, None, False),
    (((1, 1),), 1 << 64, 0, True),
    (((1, 2),), 0, 0, False),
    (((1, 1), (2, 1)), 0, 0, False),
    ((), 0, 0, False),
))
def test_only_an_unchanged_pointer_origin_can_be_reclassified_at_a_join(origin, atoms, offset, image, expected):
    projector = SimpleNamespace(_fresh_atoms={1} if origin == "fresh" else set(),
                                _nonstack_atoms={1} if origin == "nonstack" else set())
    expression = _AddressExpression(atoms, offset, 8, image)
    assert _Projector._is_nonstack(projector, expression) is expected


@pytest.fixture(params=("sparse", "dense"))
def imported(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    _, normalized = _analyze(_function())
    (window,) = normalized.nonstack_spans
    assert window.size == 1
    assert normalized.forward_inputs.nonstack_spans == normalized.nonstack_spans
    reader = next(effect.operation_key for effect in normalized.effects
                  if effect.operation_key.endswith(":LOAD")
                  and any(type(item) is ResolvedStorage and item.span == window for item in effect.reads))
    return normalized, window, reader


def test_original_one_byte_import_proof_is_preserved(imported):
    normalized, window, reader = imported
    found, _ = probe(normalized, reader, (window,))
    assert found[window] is not None


@pytest.mark.parametrize("offset,width", ((1, 1), (-1, 1), (0, 2), (-1, 2)))
def test_probe_rechecks_its_complete_access_set_and_revokes_an_expanded_object(imported, offset, width):
    normalized, window, reader = imported
    outside = ByteSpan(window.object_id, window.start + offset, width)
    before = normalized.forward_inputs
    found, _ = probe(normalized, reader, (window, outside))
    assert found[window] is None and found[outside] is None
    assert normalized.forward_inputs is before
    original, _ = probe(normalized, reader, (window,))
    assert original[window] is not None


def test_pointer_origin_labels_without_the_byte_certificate_grant_no_exclusion(imported):
    normalized, window, reader = imported
    without = replace(normalized, forward_inputs=replace(normalized.forward_inputs, nonstack_spans=frozenset()))
    found, _ = probe(without, reader, (window,))
    assert found[window] is None


@pytest.mark.parametrize("role", ("call-read", "implicit-write"))
def test_normalized_call_and_implicit_accesses_are_included_in_window_validation(imported, role):
    normalized, window, _ = imported
    unit = normalized.forward_inputs.effect_unit
    candidates = frozenset((window.object_id,))
    assert _bounded_nonstack_objects(unit, candidates, (window,)) == candidates
    block = unit.blocks[0]
    outside = ResolvedStorage(ByteSpan(window.object_id, window.end, 1))
    added = ObservedEffect("normalized-call~ld999", EffectKind.COPY,
                           reads=(outside,) if role == "call-read" else (),
                           writes=(outside,) if role == "implicit-write" else (), block_key=block.key)
    expanded = replace(unit, blocks=(replace(block, effects=(*block.effects, added)), *unit.blocks[1:]))
    assert _bounded_nonstack_objects(expanded, candidates, (window,)) == frozenset()


def test_unknown_address_writer_is_not_excluded_by_a_valid_import_window(imported):
    normalized, window, reader = imported
    before = normalized.forward_inputs
    blocks = []
    key = "unknown-address-write"
    for block in before.effect_unit.blocks:
        effects = []
        for effect in block.effects:
            if effect.operation_key == reader:
                effects.append(ObservedEffect(key, EffectKind.UNKNOWN_WRITE,
                                              memory_write=UnresolvedMemoryAccess(None, 8), block_key=block.key))
            effects.append(effect)
        blocks.append(replace(block, effects=tuple(effects)))
    changed = replace(normalized, forward_inputs=replace(before, effect_unit=replace(before.effect_unit,
                                                                                   blocks=tuple(blocks))))
    found, _ = probe(changed, reader, (window,))
    assert found[window] is None


@pytest.mark.parametrize("scope", ("function", "run"))
def test_window_check_hard_exhaustion_is_not_published_as_success(monkeypatch, scope):
    from synthetic import program_units
    from tdo_v2 import may_alias
    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.normalize import NormalizationFailureReason, UnresolvedNormalizedFunction

    attempts = []

    def exhausted(*args):
        attempts.append(1)
        raise AnalysisBudgetExceeded("work", "nonstack-byte-windows", scope=scope)

    monkeypatch.setattr(may_alias, "_bounded_nonstack_objects", exhausted)
    # Two unrelated memory objects ensure the existing alias stage is run.
    function = FunctionBuilder().ins(store(reg(RDI), reg(RDX)), store(const(0x400000), reg(RDX))).ret()
    provenance = {}
    result = analyze_units(program_units(function), record_provenance=provenance)["1:1000"]
    assert attempts and isinstance(result.normalized, UnresolvedNormalizedFunction)
    expected = NormalizationFailureReason.ANALYSIS_BUDGET if scope == "function" else \
        NormalizationFailureReason.ANALYSIS_RUN_BUDGET
    assert result.normalized.reason is expected and result.summary is None and provenance == {}
