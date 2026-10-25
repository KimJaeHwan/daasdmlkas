"""Summarized calls and the private-frame rule (docs 25.27): the registers a
complete callee effect reads are what it observes; an output read from the
stack pointer, or an effect not exported whole, makes the call a stack
escape (``ProvenCallEffect.escapes_stack``)."""

import pytest

from program_oracle import check_program
from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load, op,
    program_units, ram, reg, slice_from, store, tmp,
)
from test_index_addresses import _load_node
from tdo_v2.interprocedural import analyze_units

LEAF = CODE_BASE + 0x800


@pytest.fixture(params=("sparse", "dense"))
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def _indexed_leaf(output=RAX):
    t = tmp(0x300)
    return (FunctionBuilder(entry=LEAF)
            .ins(op("INT_MULT", [reg(RDX), const(8)], t), add(t, t, reg(RCX)), load(reg(output), t)).ret())


def _caller(setup=()):
    """[rsp+0x10] = rbx; setup; call LEAF; [rdi - 0x38] = rdx; r9 = [rsp+0x10].
    The write is through an entry value: kept out of the frame slot only
    while no stack-derived value has escaped."""
    t, u = tmp(0x100), tmp(0x200)
    builder = (FunctionBuilder().sub_rsp(0x40)
               .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RBX))))
    for row in setup:
        builder.ins(*row)
    builder.call(LEAF).ins(add(u, reg(RDI), const(-0x38 % (1 << 64))), store(u, reg(RDX)))
    reload = len(builder._rows)
    builder.ins(add(t, reg(RSP), const(0x10)), load(reg(R9), t)).add_rsp(0x40).ret()
    return builder, reload


def _run(leaf, setup=()):
    caller, reload = _caller(setup)
    results = analyze_units(program_units(caller, leaf))
    analyzed = results["1:1000"]
    (effect,) = [row for key, row in analyzed.proven.items() if key.endswith(":CALL")]
    found = slice_from(analyzed.normalized, _load_node(analyzed.normalized, reload))
    return effect, found


def _private(found):
    """The reload reads rbx only: the write through rdi was kept out."""
    return found.is_complete and not set(range(RDX, RDX + 8)) & found.register_bytes


STACK_RCX = ((add(reg(RCX), reg(RSP), const(0x10)),),)    # rcx = a frame address


def test_a_callee_returning_a_register_it_receives_observes_that_register():
    """rax = rcx; ret with rcx a frame address: the result is that address,
    which the caller's taint does not follow -- the call is an escape."""
    effect, found = _run(FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).ret(), STACK_RCX)
    assert effect.observes_registers and not effect.escapes_stack
    assert [(span.start, span.size) for span in effect.observed_registers] == [(RCX, 8)]
    assert not _private(found)


def test_a_callee_reading_another_register_keeps_the_frame_private():
    """rax = rdx + 1: rcx (a frame address) is neither read nor kept."""
    effect, found = _run(FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDX), const(1))).ret(), STACK_RCX)
    assert [(span.start, span.size) for span in effect.observed_registers] == [(RDX, 8)]
    assert _private(found)


def test_without_a_frame_address_in_a_register_the_frame_stays_private():
    effect, found = _run(FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).ret())
    assert not effect.escapes_stack and _private(found)


def test_an_output_read_from_the_stack_pointer_is_an_escape():
    """lea rax, [rsp+8]; ret: an address in the caller's frame comes back
    with no register of the caller holding one at the call."""
    effect, found = _run(FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RSP), const(8))).ret())
    assert effect.escapes_stack
    assert not _private(found)


def test_a_stack_pointer_copied_to_a_memory_output_is_an_escape():
    """COPY ram[DATA], rsp (a direct memory output, no STORE): the address of
    the caller's frame is published all the same (Astra, implementation
    review 1)."""
    effect, found = _run(FunctionBuilder(entry=LEAF).ins(copy(ram(DATA_BASE + 0x40), reg(RSP))).ret())
    assert effect.escapes_stack and not _private(found)


def test_a_partial_stack_pointer_read_is_an_escape():
    """eax = esp + 8 (the low half of the stack pointer): byte overlap."""
    effect, found = _run(FunctionBuilder(entry=LEAF).ins(add(reg(RAX, 4), reg(RSP, 4), const(8))).ret())
    assert effect.escapes_stack and not _private(found)


def test_an_effect_not_exported_whole_is_an_escape_with_every_register_observed(engines):
    """A nonlinear XOR address remains unexportable, unlike typed indexing:
    the unknown result can contain a frame address."""
    t = tmp(0x300)
    leaf = (FunctionBuilder(entry=LEAF)
            .ins(op("INT_XOR", [reg(RCX), reg(RDX)], t), load(reg(RAX), t)).ret())
    effect, found = _run(leaf)
    assert effect.preserves_memory and effect.observed_registers is None and effect.observes_registers
    assert effect.escapes_stack
    assert not _private(found)


def test_a_complete_indexed_load_without_frame_inputs_observes_only_base_and_index(engines):
    effect, found = _run(_indexed_leaf())
    assert effect.preserves_memory and effect.observes_registers and not effect.escapes_stack
    assert {(span.start, span.size) for span in effect.observed_registers} == {(RCX, 8), (RDX, 8)}
    assert _private(found)


@pytest.mark.parametrize("frame_input", (RCX, RDX))
def test_a_frame_address_in_either_indexed_load_input_stops_private_frame_separation(engines, frame_input):
    effect, found = _run(_indexed_leaf(), ((add(reg(frame_input), reg(RSP), const(0x10)),),))
    assert not effect.escapes_stack
    assert {(span.start, span.size) for span in effect.observed_registers} == {(RCX, 8), (RDX, 8)}
    assert not _private(found)


def test_an_indexed_loaded_pointer_returned_in_rdi_cannot_hide_a_published_current_frame_address(engines):
    """Publish this frame explicitly; entry memory alone cannot contain it
    under entry-values-do-not-address-the-new-frame. The callee returns it
    in RDI and the caller writes through it, after clearing its temporary."""
    address, pointer = tmp(0x100), tmp(0x200)
    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(add(pointer, reg(RSP), const(0x10)), store(pointer, reg(RBX)))
              .ins(op("INT_MULT", [reg(RDX), const(8)], address), add(address, address, reg(RCX)),
                   store(address, pointer), copy(pointer, const(0)))
              .call(LEAF).ins(store(reg(RDI), reg(RSI))))
    reload = len(caller._rows)
    caller.ins(add(pointer, reg(RSP), const(0x10)), load(reg(R9), pointer)).add_rsp(0x80).ret()
    units = program_units(caller, _indexed_leaf(RDI))
    analyzed = analyze_units(units)["1:1000"]
    (effect,) = analyzed.proven.values()
    assert not effect.escapes_stack
    assert {(span.start, span.size) for span in effect.observed_registers} == {(RCX, 8), (RDX, 8)}
    found = slice_from(analyzed.normalized, _load_node(analyzed.normalized, reload))
    assert not found.is_complete or set(range(RSI, RSI + 8)) <= found.register_bytes
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(8),
                           register_pools=lambda seed: {RSP: 0x70000000, RCX: 0x72000000,
                                                         RDX: seed & 3, RBX: 0x12340000 + seed,
                                                         RSI: 0x56780000 + seed},
                           havoc_calls=(REG, RSP, 8))
    assert report.runs == 8 and report.checked and report.through_calls
    assert not report.silent and not report.unsupported and not report.place_failed


def test_a_callee_with_an_inner_call_is_an_escape():
    inner = FunctionBuilder(entry=CODE_BASE + 0x900).ins(copy(reg(RSI), reg(R8))).ret()
    leaf = FunctionBuilder(entry=LEAF).call(CODE_BASE + 0x900).ret()
    caller, _ = _caller()
    results = analyze_units(program_units(caller, leaf, inner))
    (effect,) = [row for key, row in results["1:1000"].proven.items() if key.endswith(":CALL")]
    assert effect.escapes_stack and effect.observed_registers is None


def test_a_declared_model_keeps_its_declared_observes_and_never_escapes():
    from test_external_models import _analyze, _memcpy_caller

    results = _analyze(_memcpy_caller())
    (effect,) = results["1:1000"].proven.values()
    assert not effect.escapes_stack and effect.observes_registers and effect.observed_registers is None
