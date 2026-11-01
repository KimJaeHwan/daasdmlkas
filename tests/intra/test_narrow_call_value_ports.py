"""Body-derived scalar byte identities, distinct from pointer allocation facts.

The identity tests use no injected call contracts: original COPY/STORE/LOAD
bodies must produce the narrow identity themselves. The final isolated
normalization-policy regression uses an explicit allocator-like contract;
it is not claimed as a body proof. A raw short register write is not an
implicit zero extension of its unmodified upper bytes.
"""

from dataclasses import replace

import pytest

from forward_oracle import check_forward
from synthetic import (REG, RAX, RBX, RCX, RDI, RDX, RSP, FunctionBuilder, add, const,
                       copy, load, op, program_units, reg, store, tmp)
from tdo_v2._call_value_ports import scalar_call_rows
from tdo_v2.forward import forward_facts
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer


CALLEE, INNER, VALUE = 0x1800, 0x1900, 0x1234abef


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def _engine(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "0")


def _fixture(width, kind="reg", *, extend=True, nested=False):
    value = VALUE & ((1 << (8 * width)) - 1)
    caller = FunctionBuilder().sub_rsp(0x38)
    if kind == "reg":
        caller.ins(copy(reg(RCX, width), const(value, width)))
    elif kind == "mem":
        caller.ins(add(reg(RCX), reg(RSP), const(0x10)), store(reg(RCX), const(value, width)))
    elif kind == "store":
        caller.ins(add(reg(RCX), reg(RSP), const(0x10)), copy(reg(RDX, width), const(value, width)))
    else:
        raise AssertionError(kind)
    call = f"1:{caller._address(len(caller._rows)):x}:2:CALL"
    caller.call(CALLEE)
    if kind == "store":
        caller.ins(add(tmp(0x500), reg(RSP), const(0x10)), load(reg(RAX, width), tmp(0x500)))
    address = reg(RAX)
    if extend:
        address = tmp(0x510)
        caller.ins(op("INT_ZEXT", [reg(RAX, width)], address))
    key = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RDI), address)).add_rsp(0x38).ret()
    leaf = FunctionBuilder(entry=INNER if nested else CALLEE)
    if kind == "reg":
        leaf.ins(copy(reg(RAX, width), reg(RCX, width)), copy(reg(RCX, width), const(7, width)))
    elif kind == "mem":
        leaf.ins(load(reg(RAX, width), reg(RCX)), store(reg(RCX), const(7, width)))
    else:
        leaf.ins(store(reg(RCX), reg(RDX, width)))
    leaf.ret()
    functions = [caller, leaf]
    if nested:
        functions.append(FunctionBuilder(entry=CALLEE).sub_rsp(0x28).call(INNER).add_rsp(0x28).ret())
    units = program_units(*functions)
    results = analyze_units(units)
    return results, units, call, key, value


@pytest.mark.parametrize("width", (1, 2, 4))
@pytest.mark.parametrize("kind", ("reg", "mem", "store"))
def test_original_narrow_copy_load_and_store_produce_and_consume_exact_scalar_bytes(width, kind):
    results, units, call, key, value = _fixture(width, kind)
    item, callee = results["1:1000"], results[f"1:{CALLEE:x}"]
    normalized = item.normalized
    # A narrow scalar identity and the existing eight-byte saved return
    # address identity must coexist; one global "summary pointer width"
    # cannot suppress either original run.
    effects = dict(normalized.proven_call_effects)[call]
    runs = (*effects.runs, *effects.memory_runs)
    selected = [(i, run) for i, run in enumerate(runs)
                if run.value is not None and run.value[0] in ("same_reg", "same_mem")
                and (run.writes[0].size if hasattr(run, "writes") else run.write.size) == width]
    assert selected
    assert any(run.value is not None and run.value[0] == "same_mem" and run.writes[0].size == 8
               for run in effects.runs)
    ports = scalar_call_rows(normalized)
    for index, run in selected:
        port = ports[f"{call}~{index}"]
        assert port.width == width and run.value[2] is False
        assert port.row[0] == ("mem" if kind == "mem" else "reg")
    facts = {fact.operation: fact for fact in forward_facts(normalized, item.unit)}
    assert facts[key].claim.single_number() == value
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_forward(item.unit, [facts[key]], seeds=range(3),
                           register_pools=lambda _: {RSP: 0x70000000},
                           program=program, havoc_calls=(REG, RSP, 8))
    assert report.checked == 3 and not report.failures and not report.skipped
    assert all(not result.declared and not result.test_only_inputs for result in results.values())
    assert not effects.fresh_registers and not effects.same_object_registers
    assert callee.normalized.memory_ssa is not None


@pytest.mark.parametrize("width", (1, 2, 4))
def test_two_body_boundaries_preserve_the_same_narrow_entry_source(width):
    results, _, call, key, value = _fixture(width, nested=True)
    caller, wrapper = results["1:1000"], results[f"1:{CALLEE:x}"]
    run, = [run for exit_ in wrapper.summary.exits for run in exit_.runs
            if run.span.object_id.kind.value == "register_file" and run.span.start == RAX and run.span.size == width]
    assert run.value is not None and run.value[0] == "same" and run.value[2] is False
    assert (run.value[1].start, run.value[1].size) == (RCX, width)
    assert any(key.startswith(call + "~") and port.width == width
               for key, port in scalar_call_rows(caller.normalized).items())
    fact = next(fact for fact in forward_facts(caller.normalized, caller.unit) if fact.operation == key)
    assert fact.claim.single_number() == value


@pytest.mark.parametrize("width", (1, 2, 4))
def test_narrow_copy_does_not_zero_unwritten_upper_register_bytes(width):
    results, _, _, key, _ = _fixture(width, extend=False)
    item = results["1:1000"]
    fact = next((fact for fact in forward_facts(item.normalized, item.unit) if fact.operation == key), None)
    assert fact is None or fact.claim.single_number() is None


@pytest.mark.parametrize("same", (False, True))
def test_original_join_is_not_replaced_with_one_arbitrary_narrow_source(same):
    width, flag = 4, tmp(0x600, 1)
    callee = FunctionBuilder(entry=CALLEE).cbranch("other", flag, copy(flag, reg(RDI, 1)))
    callee.ins(copy(reg(RAX, width), reg(RCX, width))).branch("join")
    callee.label("other").ins(copy(reg(RAX, width), reg(RCX if same else RDX, width)))
    callee.label("join").ret()
    results = analyze_units(program_units(callee))
    item = results[f"1:{CALLEE:x}"]
    run, = [run for exit_ in item.summary.exits for run in exit_.runs
            if run.span.object_id.kind.value == "register_file" and run.span.start == RAX and run.span.size == width]
    assert len(run.definitions) > 1 or any(item.normalized.memory_ssa.definitions[i].kind is MemoryDefinitionKind.JOIN
                                          for i in run.definitions)
    if same:
        assert run.value is not None and run.value[0] == "same"
        assert (run.value[1].start, run.value[1].size, run.value[2]) == (RCX, width, False)
    else:
        assert run.value is None
    # Both original definitions and their raw JOIN evidence remain available.
    writers = {definition.operation_key for definition in item.normalized.memory_ssa.definitions
               if definition.span.object_id.kind.value == "register_file" and definition.span.start == RAX}
    assert {"1:1804:0:COPY", "1:180c:0:COPY"} <= writers


@pytest.mark.parametrize("variant", ("call-kill", "stale-frame", "partial-unknown"))
def test_unproved_narrow_origins_are_not_promoted_to_a_complete_scalar_identity(variant):
    width = 4
    callee = FunctionBuilder(entry=CALLEE)
    if variant == "stale-frame":
        callee.sub_rsp(0x28).ins(load(reg(RAX, width), reg(RSP))).add_rsp(0x28)
    else:
        callee.ins(copy(reg(RAX, width), reg(RCX, width)))
        if variant == "call-kill":
            callee.call(0x1f00)
        else:
            callee.ins(copy(reg(RAX, 1), reg(RDX, 1)))
    callee.ret()
    item = analyze_units(program_units(callee))[f"1:{CALLEE:x}"]
    rax = [run for exit_ in item.summary.exits for run in exit_.runs
           if run.span.object_id.kind.value == "register_file" and run.span.start < 4 and run.span.end > 0]
    assert rax
    assert not any(run.span.start == RAX and run.span.size == width and run.value is not None for run in rax)
    assert all(run.value is None or run.value[0] != "nonstack" for run in rax)


def test_independent_narrow_scalar_does_not_change_existing_full_pointer_uniqueness():
    from tdo_v2.call_summary_effects import ProvenCallEffect, ProvenRunEffect, StackRestoration
    from tdo_v2.span_geometry import ByteSpan

    results, _, call, _, _ = _fixture(4)
    item = results["1:1000"]
    original = dict(item.normalized.proven_call_effects)[call].runs[0]
    registers = original.writes[0].object_id
    pointer_source, scalar_source = ByteSpan(registers, RCX, 8), ByteSpan(registers, RDX, 4)
    pointer = ProvenRunEffect((ByteSpan(registers, RAX, 8),), (pointer_source,),
                              value=("same_reg", pointer_source, True))
    scalar = replace(original, writes=(ByteSpan(registers, RBX, 4),), reads=(scalar_source,),
                     value=("same_reg", scalar_source, False))
    # Test-only contract for the normalization policy, not a claim that the
    # original COPY body is an allocator. No new runtime assumption is added.
    effect = ProvenCallEffect("allocator-like-contract", (pointer, scalar), (), preserves_memory=True,
                              stack_restoration=StackRestoration.PROVEN)
    normalized = FunctionNormalizer().normalize(item.unit, proven_call_effects={call: effect})
    rows = dict(normalized.pointer_rows)
    assert rows[call + "~0"][3:] == (True, True)
    assert call + "~0" not in scalar_call_rows(normalized)  # null/fresh is still not a scalar identity
    assert scalar_call_rows(normalized)[call + "~1"].width == 4


@pytest.mark.parametrize("source_width,output_width", ((4, 8), (8, 4), (2, 4)))
def test_scalar_lowering_cannot_use_a_different_width_even_with_matching_summary_pointer_width(source_width,
                                                                                              output_width):
    from tdo_v2.call_summary_effects import _pointer_value
    from tdo_v2.span_geometry import ByteSpan

    results, _, call, _, _ = _fixture(4)
    registers = results["1:1000"].proven[call].runs[0].writes[0].object_id
    source, output = ByteSpan(registers, RCX, source_width), ByteSpan(registers, RAX, output_width)
    markers = frozenset((("pointer", ("same", source, False)), source))
    assert _pointer_value(markers, False, (output,), output_width, lambda span: None) is None
