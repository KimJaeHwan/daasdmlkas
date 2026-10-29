"""Exact scalar bits survive only unanimous, full-width summary claims."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace

import pytest

from synthetic import (
    CODE_BASE, DATA_BASE, RAX, RCX, RDX, FunctionBuilder, add, const, copy, normalize_with_observation,
    op, program_units, reg, store, tmp,
)
from tdo_v2.call_summary_effects import derive_composed_call_effect, derive_proven_call_effect
from tdo_v2.constant_value import ExactConstant
from tdo_v2.function_summary import (
    FUNCTION_SUMMARY_VERSION, ExitSummary, FunctionSummary, SummaryKind, SummaryRun, _constant_values,
    summarize_function,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.span_geometry import ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind
from tdo_v2.summary_templates import (
    ENGINE_SEMANTICS_VERSION, TEMPLATE_VERSION, TemplateError, TemplateRefused, _ObjectTable, instantiate,
)


PROGRAM = StorageScopeId(StorageScopeKind.PROGRAM, b"p" * 32)
FUNCTION = StorageScopeId(StorageScopeKind.FUNCTION, b"f" * 32)
REGISTERS = StorageObjectId(StorageObjectKind.REGISTER_FILE, PROGRAM, 0)
MEMORY = StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, FUNCTION, 1)
BIAS = 1 << 64


def _run(span=None, literal=ExactConstant(8, 0), **changes):
    base = SummaryRun(span or ByteSpan(REGISTERS, RAX, 8), SummaryKind.COMPUTED, (1,),
                      ("write",), (), (), (), (), literal=literal)
    return replace(base, **changes)


def _summary(*exits):
    return FunctionSummary(FUNCTION_SUMMARY_VERSION,
                           tuple(ExitSummary(f"exit{i}", tuple(runs)) for i, runs in enumerate(exits)), (), ())


def _effect(*exits, excluded=()):
    return derive_proven_call_effect(_summary(*exits), "test", REGISTERS, 128, excluded=excluded,
                                     anchors={MEMORY: (ByteSpan(REGISTERS, RCX, 8), 1)})


def _template(run):
    table = _ObjectTable({MEMORY: (ByteSpan(REGISTERS, RCX, 8), 1)})
    row = table.run(run)
    return {"exits": [{"block": "dll:exit", "runs": [row]}], "unknown_writers": [],
            "writer_objects": [], "inner_calls": [], "register_deltas": [], "independent_delta_proofs": [], "dead_exits": [],
            "writer_conditions": [], "stack_values_out": False, "objects": table.rows}


@pytest.mark.parametrize("size,value", [(1, 0), (1, 255), (8, (1 << 64) - 1), (16, (1 << 128) - 1)])
def test_exact_constant_is_fixed_width_and_immutable(size, value):
    literal = ExactConstant(size, value)
    assert hash(literal) == hash(ExactConstant(size, value))
    with pytest.raises(FrozenInstanceError):
        literal.unsigned = 0


@pytest.mark.parametrize("size,value,error", [
    (True, 0, TypeError), (8, False, TypeError), (8.0, 0, TypeError), (8, "0", TypeError),
    (0, 0, ValueError), (17, 0, ValueError), (1, -1, ValueError), (1, 256, ValueError),
])
def test_exact_constant_rejects_coercion_and_out_of_range(size, value, error):
    with pytest.raises(error):
        ExactConstant(size, value)


def test_summary_attaches_only_unanimous_exact_width_finished_definitions(monkeypatch):
    from tdo_v2 import relative_memory

    run = _run(literal=None, definitions=(1, 2))
    exits = [ExitSummary("exit", (run,))]
    requests = []

    def values(normalized, observation, asked):
        requests.append(asked)
        return {(1, run.span): ExactConstant(8, 7), (2, run.span): ExactConstant(8, 7)}

    monkeypatch.setattr(relative_memory, "definition_constants", values, raising=False)
    assert _constant_values(None, None, exits)[0].runs[0].literal == ExactConstant(8, 7)
    assert requests == [{(1, run.span), (2, run.span)}]


@pytest.mark.parametrize("case", ["missing", "different", "width", "none", "debt", "crossed", "identity"])
def test_summary_does_not_promote_incomplete_or_unsafe_proof(monkeypatch, case):
    from tdo_v2 import relative_memory

    run = _run(literal=None, definitions=(1, 2))
    data = {(1, run.span): ExactConstant(8, 7), (2, run.span): ExactConstant(8, 7)}
    if case == "missing":
        del data[(2, run.span)]
    elif case == "different":
        data[(2, run.span)] = ExactConstant(8, 8)
    elif case == "width":
        data[(2, run.span)] = ExactConstant(4, 7)
    elif case == "none":
        data = None
    elif case == "debt":
        run = replace(run, debts=("call_clobber_read",))
    elif case == "crossed":
        run = replace(run, crossed=("call:clobber",))
    else:
        run = replace(run, kind=SummaryKind.IDENTITY)
    monkeypatch.setattr(relative_memory, "definition_constants", lambda *args: data, raising=False)
    assert _constant_values(None, None, [ExitSummary("exit", (run,))])[0].runs[0].literal is None


@pytest.mark.parametrize("memory", [False, True])
def test_call_effect_retains_equal_literals_on_every_exit_without_pointer_claim(memory):
    span = ByteSpan(MEMORY, BIAS, 8) if memory else ByteSpan(REGISTERS, RAX, 8)
    source = ByteSpan(REGISTERS, RCX, 8)
    run = _run(span, sources=(source,), origins=("original-source",))
    effect = _effect((run,), (replace(run, writers=("other-write",)),))
    (result,) = effect.memory_runs if memory else effect.runs
    assert result.literal == ExactConstant(8, 0)
    assert result.value is None   # numeric zero is not fresh / same / nonstack
    assert result.reads == (source,) and result.origins == ("original-source",)
    assert effect.fresh_registers == () and effect.same_object_registers == ()


@pytest.mark.parametrize("other", ["different", "missing", "identity", "unknown", "debt", "unmentioned"])
def test_call_effect_never_promotes_conflicting_or_may_write_literals(other):
    run = _run()
    changes = {"different": {"literal": ExactConstant(8, 1)}, "missing": {"literal": None},
               "identity": {"kind": SummaryKind.IDENTITY}, "unknown": {"kind": SummaryKind.UNKNOWN},
               "debt": {"debts": ("call_clobber_read",)}}
    second = () if other == "unmentioned" else (replace(run, **changes[other]),)
    effect = _effect((run,), second)
    assert all(result.literal is None for result in effect.runs)


def test_partial_output_drops_literal_and_adjacent_equal_stores_stay_separate():
    run = _run()
    effect = _effect((run,), excluded=(ByteSpan(REGISTERS, RAX + 4, 4),))
    assert effect.runs and all(result.literal is None for result in effect.runs)
    other = _run(ByteSpan(REGISTERS, RAX + 8, 8))
    effect = _effect((run, other))
    assert [result.writes for result in effect.runs] == [(run.span,), (other.span,)]
    assert [result.literal for result in effect.runs] == [ExactConstant(8, 0)] * 2


def test_memory_partial_exit_and_different_widths_cannot_reuse_original_literal():
    span = ByteSpan(MEMORY, BIAS, 8)
    original = _run(span)
    partial = _run(ByteSpan(MEMORY, BIAS, 4), ExactConstant(4, 0))
    effect = _effect((original,), (partial,))
    assert effect.memory_runs and all(run.literal is None for run in effect.memory_runs)


def test_several_targets_require_unanimous_literals_and_preserve_contested_memory_debt():
    run = _run()
    members = ((_summary((run,)), {}), (_summary((run,)), {}))
    effect = derive_composed_call_effect(members, "targets", REGISTERS, 128)
    assert effect.runs[0].literal == ExactConstant(8, 0)
    members = (members[0], (_summary((replace(run, literal=ExactConstant(8, 1)),)), {}))
    effect = derive_composed_call_effect(members, "targets", REGISTERS, 128)
    assert effect.runs[0].literal is None
    memory = _run(ByteSpan(MEMORY, BIAS, 8))
    members = tuple((_summary((memory,)), {MEMORY: (ByteSpan(REGISTERS, RCX, 8), 1)}) for _ in range(2))
    effect = derive_composed_call_effect(members, "targets", REGISTERS, 128)
    # Integrated fixed-anchor composition now retains their physical output.
    # It does not claim a whole-literal value from matching dependencies.
    (output,) = effect.memory_runs
    assert output.write.anchor == ByteSpan(REGISTERS, RCX, 8)
    assert output.literal is None and not effect.unknown_memory
    # Actually conflicting bases remain contested, not silently unified.
    members = (members[0], (members[1][0], {MEMORY: (ByteSpan(REGISTERS, RCX + 8, 8), 1)}))
    effect = derive_composed_call_effect(members, "targets", REGISTERS, 128)
    assert not effect.memory_runs and effect.unknown_memory


@pytest.mark.parametrize("memory", [False, True])
def test_template_roundtrip_keeps_scalar_bits_separate_and_versioned(memory):
    span = ByteSpan(MEMORY, BIAS, 8) if memory else ByteSpan(REGISTERS, RAX, 8)
    raw = _template(_run(span, ExactConstant(8, (1 << 64) - 1)))
    summary, anchors = instantiate(raw, "test", REGISTERS, 1)
    (result,) = summary.exits[0].runs
    assert result.literal == ExactConstant(8, (1 << 64) - 1) and result.value is None
    effect = derive_proven_call_effect(summary, "test", REGISTERS, 128, anchors=anchors)
    assert (effect.memory_runs if memory else effect.runs)[0].literal == result.literal
    assert TEMPLATE_VERSION == 6 and ENGINE_SEMANTICS_VERSION == 29


@pytest.mark.parametrize("pointer", [("nonstack",), ("same", ByteSpan(REGISTERS, RCX, 8), False)])
def test_template_rejects_dual_scalar_and_pointer_claim_on_export_and_import(pointer):
    with pytest.raises(TemplateRefused, match="both scalar literal and pointer"):
        _template(_run(value=pointer))
    raw = _template(_run())
    pointer_only = _template(_run(literal=None, value=pointer))
    raw["exits"][0]["runs"][0]["value"] = pointer_only["exits"][0]["runs"][0]["value"]
    with pytest.raises(TemplateError, match="both scalar literal and pointer"):
        instantiate(raw, "test", REGISTERS, 1)


@pytest.mark.parametrize("bad", [
    {"byte_size": True, "unsigned": 0}, {"byte_size": 8, "unsigned": False},
    {"byte_size": 8, "unsigned": -1}, {"byte_size": 8, "unsigned": 1 << 64},
    {"byte_size": 4, "unsigned": 0}, {"byte_size": 17, "unsigned": 0},
    {"byte_size": 8, "unsigned": 0, "fresh": True}, {"unsigned": 0}, [8, 0],
])
def test_template_rejects_malformed_or_wrong_width_literal(bad):
    raw = deepcopy(_template(_run()))
    raw["exits"][0]["runs"][0]["literal"] = bad
    with pytest.raises(TemplateError):
        instantiate(raw, "test", REGISTERS, 1)


@pytest.mark.parametrize("changes", [{"kind": SummaryKind.IDENTITY}, {"kind": SummaryKind.UNKNOWN},
                                         {"debts": ("opaque_call_write",)}, {"crossed": ("call:opaque",)},
                                         {"literal": ExactConstant(4, 0)}])
def test_template_export_rejects_invalid_declared_literal(changes):
    with pytest.raises(TemplateRefused):
        _template(replace(_run(), **changes))


@pytest.mark.parametrize("field,value", [("kind", "unknown"), ("kind", "identity"),
                                          ("debts", ["call_clobber_read"]), ("crossed", ["call:opaque"])])
def test_template_import_rejects_literals_on_unproven_runs(field, value):
    raw = _template(_run())
    raw["exits"][0]["runs"][0][field] = value
    with pytest.raises(TemplateError):
        instantiate(raw, "test", REGISTERS, 1)


def test_actual_finished_summary_gets_ctor_style_full_width_zero():
    builder = FunctionBuilder().ins(copy(reg(RAX), const(0)), store(reg(RCX), reg(RAX))).ret()
    analyzed = analyze_units(program_units(builder))["1:1000"]
    summary = analyzed.summary
    written = [run for item in summary.exits for run in item.runs
               if any(key.endswith((":COPY", ":STORE")) for key in run.writers)
               and run.span.object_id.kind is not StorageObjectKind.FUNCTION_UNIQUE]
    assert len(written) == 2 and all(run.literal == ExactConstant(run.span.size, 0) for run in written)
    assert all(run.value is None for run in written)


def _register_literals(builder):
    normalized, observation = normalize_with_observation(builder)
    summary = summarize_function(normalized, observation)
    return {run.span: run.literal for item in summary.exits for run in item.runs
            if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE
            and RAX <= run.span.start < RAX + 8}


def test_ctor_xor_zext_and_two_header_stores_have_separate_full_width_zeros():
    offset, value = tmp(0x100), tmp(0x108)
    builder = (FunctionBuilder()
               .ins(op("INT_XOR", [reg(RAX, 4), reg(RAX, 4)], reg(RAX, 4)),
                    op("INT_ZEXT", [reg(RAX, 4)], reg(RAX)))
               .ins(copy(value, reg(RAX)), store(reg(RCX), value))
               .ins(add(offset, reg(RCX), const(8)), copy(value, reg(RAX)), store(offset, value)).ret())
    analyzed = analyze_units(program_units(builder))["1:1000"]
    summary = analyzed.summary
    stores = [run for item in summary.exits for run in item.runs
              if any(key.endswith(":STORE") for key in run.writers)]
    assert len(stores) == 2 and all(run.literal == ExactConstant(8, 0) for run in stores)
    effect = derive_proven_call_effect(summary, "ctor", stores[0].sources[0].object_id, 128,
                                      anchors=analyzed.anchors)
    assert [run.literal for run in effect.memory_runs] == [ExactConstant(8, 0)] * 2
    assert all(run.value is None and not run.keeps_old for run in effect.memory_runs)


@pytest.mark.parametrize("other,expected", [(7, ExactConstant(8, 7)), (9, None)])
def test_actual_branch_join_requires_one_constant(other, expected):
    builder = (FunctionBuilder().cbranch("other", reg(RCX, 1))
               .ins(copy(reg(RAX), const(7))).branch("join")
               .label("other").ins(copy(reg(RAX), const(other)))
               .label("join").ret())
    values = _register_literals(builder)
    assert values and set(values.values()) == {expected}


def test_actual_partial_unknown_overwrite_does_not_invent_a_wider_literal():
    builder = (FunctionBuilder().ins(copy(reg(RAX), const(0xA1B2C3D4E5F60718)))
               .ins(copy(reg(RAX, 4), reg(RDX, 4))).ret())
    values = _register_literals(builder)
    assert values and any(span.size == 4 and value == ExactConstant(4, 0xA1B2C3D4)
                          for span, value in values.items())
    assert all(value is None for span, value in values.items() if span.start == RAX)


def test_actual_opaque_call_drops_literal_but_later_exact_write_recovers_it():
    before = FunctionBuilder().ins(copy(reg(RAX), const(7))).call(CODE_BASE + 0x800).ret()
    after = (FunctionBuilder().ins(copy(reg(RAX), const(7))).call(CODE_BASE + 0x800)
             .ins(copy(reg(RAX), const(9))).ret())
    assert set(_register_literals(before).values()) == {None}
    assert set(_register_literals(after).values()) == {ExactConstant(8, 9)}


@pytest.mark.parametrize("opcode,expected", [("INT_ZEXT", 0x80000000), ("INT_SEXT", 0xFFFFFFFF80000000)])
def test_actual_width_conversion_is_not_pointer_provenance(opcode, expected):
    builder = FunctionBuilder().ins(op(opcode, [const(0x80000000, 4)], reg(RAX))).ret()
    assert set(_register_literals(builder).values()) == {ExactConstant(8, expected)}


@pytest.mark.parametrize("relocation", [True, False, None])
def test_image_range_values_are_not_promoted_to_portable_numeric_literals(relocation):
    from tdo_v2.relative_memory import ImageBaseTracking

    builder = FunctionBuilder().ins(copy(reg(RAX), const(DATA_BASE + 0x100))).ret()
    with ImageBaseTracking(((CODE_BASE, DATA_BASE + 0x1000),), lambda *args: relocation):
        values = _register_literals(builder)
    assert values and set(values.values()) == {None}
