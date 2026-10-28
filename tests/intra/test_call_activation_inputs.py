"""Activation input boundaries, distinguishing raw SSA from consumer guards."""

from dataclasses import replace

import pytest

from synthetic import RAX, RCX, RDX, RSP, FunctionBuilder, add, const, load, program_units, reg, store, tmp
from tdo_v2._activation_entry import ActivationEntry, using_entry
from tdo_v2._call_activation import _first, _inputs, _memory_inputs, _normalize
from tdo_v2.constant_value import ExactConstant
from tdo_v2.forward import _analyze, probe
from tdo_v2.interprocedural import _relative_anchors, analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.relative_memory import _final_projector
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind


@pytest.fixture(autouse=True)
def forward_on(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def _case(displacement=8, width=8):
    # Displacements are relative to callee entry SP, after the observed push.
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(add(tmp(0x100), reg(RSP), const((displacement - 8) % (1 << 64))),
                   store(tmp(0x100), const(0, width)))
              .ins(add(reg(RCX), reg(RSP), const(0x10)))
              .call(0x1800).add_rsp(0x28).ret())
    callee = (FunctionBuilder(0x1800).ins(load(reg(RDX), reg(RCX)))
              .ins(add(tmp(0x200), reg(RSP), const(displacement % (1 << 64))),
                   load(reg(RAX, width), tmp(0x200))).ret())
    analyzed = analyze_units(program_units(caller, callee),
                             assume_entry_values_not_frame=False,
                             assume_opaque_callees_leave_no_stack_addresses=False)
    caller, callee = analyzed["1:1000"], analyzed["1:1800"]
    (call,) = caller.calls
    inputs = _inputs(caller, callee, call, (), None)
    assert inputs is not None
    sp, delta, obj, bias, registers, labels = inputs
    state = ActivationEntry(callee.unit.scopes.function.scope, (caller.key, call), registers, (), labels)
    normalized = _normalize(callee, state)
    return caller, callee, normalized, sp, delta, obj, bias


def _seeds(case):
    return _memory_inputs(*case, None, ())


@pytest.mark.parametrize("displacement,width", ((0, 8), (-4, 8), (4, 8), (7, 2)))
def test_original_call_push_blocks_whole_and_partial_entry_memory_inputs(displacement, width):
    case = _case(displacement, width)
    caller, callee, normalized, sp, delta, obj, bias = case
    source = ByteSpan(obj, bias + delta + displacement, width)
    call = normalized.activation_entry.context[1]
    # This is a genuine pre-push STORE in the caller's admitted raw SSA,
    # not an injected constant. It is nevertheless not callee ENTRY memory.
    identifier = probe(caller.normalized, _first(caller.normalized, call), (source,))[0][source]
    assert type(identifier) is int
    definition = caller.normalized.memory_ssa.definitions[identifier]
    assert definition.kind is MemoryDefinitionKind.DATA_WRITE
    target = next(read for read in normalized.memory_ssa.reads
                  if normalized.memory_ssa.actions[read.action_id].operation_key == "1:1804:1:LOAD"
                  and read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE)
    assert target.span.size == width and target.span.start == (1 << 64) + displacement
    assert _relative_anchors(callee.unit, normalized)[target.span.object_id] == (sp, caller.anchors[obj][1])
    assert all(normalized.memory_ssa.definitions[identifier].kind is MemoryDefinitionKind.ENTRY
               for fragment in target.fragments for identifier in fragment.definition_ids)
    values, _ = _analyze(caller.normalized, caller.unit).bind(call, (source,))
    assert values[source].single_number() == 0
    seeds, witnesses, _ = _seeds(case)
    assert not seeds and not witnesses
    assert callee.normalized.activation_entry is None


def test_original_nonoverlapping_callee_entry_fragment_has_a_constant_witness():
    case = _case()
    seeds, witnesses, _ = _seeds(case)
    assert len(seeds) == len(witnesses) == 1
    span, literal = seeds[0]
    assert span.start == (1 << 64) + 8 and literal == ExactConstant(8, 0)
    assert witnesses[0][2] == literal


def test_low_level_memory_space_anchor_mismatch_refuses_the_same_raw_constant():
    # The synthetic provider admits only one RAM space. This is explicitly a
    # consumer-boundary test of anchor metadata, not a claimed multi-space
    # raw program or a mutation of the admitted program's evidence.
    case = _case()
    assert _seeds(case)[0]
    caller, callee, normalized, sp, delta, obj, bias = case
    anchors = dict(caller.anchors)
    base, memory_space = anchors[obj]
    anchors[obj] = (base, memory_space + 100)
    foreign = replace(caller, anchors=anchors)
    seeds, witnesses, _ = _memory_inputs(foreign, callee, normalized, sp, delta, obj, bias, None, ())
    assert seeds == witnesses == ()


@pytest.mark.parametrize("language", ("x86:BE:64:default", "x86:BE:32:default"))
def test_low_level_projector_language_guard_does_not_consume_le_partial_seed(language):
    # Real x86 LE64 SSA supplies the ENTRY definition. Only the projector's
    # language parameter is varied below: this is not admitted big-endian SSA
    # (LE:32 is admitted since design C1: test_call_activation_x86_32.py).
    (item,) = analyze_units(program_units(FunctionBuilder()
        .ins(load(tmp(0x300, 16), reg(RCX))).ret()),
        assume_entry_values_not_frame=False,
        assume_opaque_callees_leave_no_stack_addresses=False).values()
    ssa = item.normalized.memory_ssa
    read = next(read for read in ssa.reads if read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
                and read.span.size == 16)
    (fragment,) = read.fragments
    (identifier,) = fragment.definition_ids
    assert ssa.definitions[identifier].kind is MemoryDefinitionKind.ENTRY
    requested = ByteSpan(read.span.object_id, read.span.start + 2, 3)
    state = ActivationEntry(ssa.function_scope, ("caller", "call"), (),
                            ((read.span, ExactConstant(16, 0x8877665544332211)),), ("input-proof",))
    with using_entry(state):
        positive = _final_projector(item.normalized, item.unit.observation)
        expression = positive._expression_for_definition(identifier, requested)
        assert expression is not None and not expression.atoms and expression.displacement == 0x554433
        guarded = _final_projector(item.normalized, item.unit.observation)
        guarded._translation_namespace = language
        result = guarded._expression_for_definition(identifier, requested)
    baseline = _final_projector(item.normalized, item.unit.observation)
    baseline._translation_namespace = language
    assert result == baseline._expression_for_definition(identifier, requested)
    assert result is None or result.atoms
