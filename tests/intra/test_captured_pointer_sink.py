"""Physical pointer sinks use the value captured by an exact settled LOAD."""

import pytest

from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDX, RSP, ZF,
    FunctionBuilder, add, const, copy, load, op, reg, store, summary_inputs,
)
from tdo_v2 import may_alias
from tdo_v2.integration.configured_boundary_demands import _direct_sink_boundary_nodes
from tdo_v2.integration.configured_function_view import _FunctionView
from tdo_v2.integration.configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from tdo_v2.integration.configured_physical_state import _FunctionPhysicalStateBackend
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.observed_boundary_projection import EMPTY_OBSERVED_BOUNDARIES
from tdo_v2.physical_state import PhysicalMemorySlice, PhysicalRegisterSlice, PhysicalStateResolver
from tdo_v2.query import BackwardSliceQuery


SINK, OPAQUE = CODE_BASE + 0x800, CODE_BASE + 0xA00


@pytest.fixture(params=("sparse", "dense"))
def engine(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    token = may_alias.ENTRY_VALUES_NOT_FRAME.set(False)
    try:
        yield
    finally:
        may_alias.ENTRY_VALUES_NOT_FRAME.reset(token)


def _view(body):
    (evidence,) = summary_inputs([body], image=False).evidences
    normalized = FunctionNormalizer().normalize(evidence.unit)
    return _FunctionView(ConfiguredFunctionAnalysis(evidence, normalized, EMPTY_OBSERVED_BOUNDARIES, ()))


def _main():
    return (FunctionBuilder().sub_rsp(0x38)
            .ins(add(reg(RBX), reg(RSP), const(0x20)))
            .ins(store(reg(RBX), reg(RCX))))


def _finish(body):
    return body.call(SINK).add_rsp(0x38).ret()


def _candidates(view, base=RDX):
    sink = max(position for position, operation in view.operations.values() if operation.opcode == "CALL")
    return _FunctionPhysicalStateBackend(view).memory_candidates(
        PhysicalMemorySlice(PhysicalRegisterSlice(base, 8), 8, 2), sink
    )


def test_exact_pointer_load_binds_to_its_captured_entry_pointer(engine):
    view = _view(_finish(_main().ins(load(reg(RDX), reg(RBX)))))
    assert _candidates(view) == _candidates(view, RCX)
    assert len(_candidates(view)) == 1


@pytest.mark.parametrize("overwrite", ("whole", "partial", "conditional"))
def test_overwriting_the_slot_after_load_does_not_retarget_the_capture(engine, overwrite):
    body = _main().ins(load(reg(RDX), reg(RBX)))
    if overwrite == "conditional":
        body.cbranch("sink", reg(ZF, 1))
    body.ins(store(reg(RBX), reg(R8, 4 if overwrite == "partial" else 8)))
    if overwrite == "conditional":
        body.label("sink")
    view = _view(_finish(body))
    assert len(_candidates(view)) == 1
    assert _candidates(view) == _candidates(view, RCX)
    assert _candidates(view) != _candidates(view, R8)


def test_an_exact_overwrite_before_load_selects_the_new_pointer(engine):
    view = _view(_finish(_main().ins(store(reg(RBX), reg(R8)))
                        .ins(load(reg(RDX), reg(RBX)))))
    assert len(_candidates(view)) == 1
    assert _candidates(view) == _candidates(view, R8)
    assert _candidates(view) != _candidates(view, RCX)


@pytest.mark.parametrize("barrier", ("partial", "opaque", "alias", "unresolved"))
def test_unsettled_pointer_reads_never_reuse_the_old_slot_value(engine, barrier):
    body = _main()
    if barrier == "partial":
        body.ins(store(reg(RBX), reg(R8, 4)))
    elif barrier == "opaque":
        body.call(OPAQUE)
    elif barrier == "alias":
        body.ins(store(reg(R9), reg(R8)))
    else:
        body.ins(op("INT_MULT", [reg(R9), reg(R8)], reg(RAX)))
        body.ins(store(reg(RAX), reg(R8)))
    view = _view(_finish(body.ins(load(reg(RDX), reg(RBX)))))
    assert _candidates(view) == ()


def test_two_conditional_captures_remain_ambiguous_at_the_sink(engine):
    body = (_main().cbranch("read", reg(ZF, 1)).ins(store(reg(RBX), reg(R8)))
            .label("read").ins(load(reg(RDX), reg(RBX))))
    view = _view(_finish(body))
    assert set(_candidates(view)) == set(_candidates(view, RCX) + _candidates(view, R8))
    assert len(_candidates(view)) == 2
    sink = max(position for position, operation in view.operations.values() if operation.opcode == "CALL")
    assert PhysicalStateResolver(_FunctionPhysicalStateBackend(view)).resolve(
        PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), 8, 2), sink
    ) is None


def test_copy_and_displacement_preserve_the_read_time_pointer(engine):
    body = (_main().ins(load(reg(RAX), reg(RBX)))
            .ins(copy(reg(RDX), reg(RAX)))
            .ins(add(reg(RDX), reg(RDX), const(16)))
            .ins(store(reg(RBX), reg(R8)))
            .ins(add(reg(RCX), reg(RCX), const(16))))
    view = _view(_finish(body))
    assert len(_candidates(view)) == 1
    assert _candidates(view) == _candidates(view, RCX)


def test_two_exact_pointer_loads_compose_without_rereading_either_slot(engine):
    body = (_main().ins(add(reg(R9), reg(RSP), const(0x28)))
            .ins(store(reg(R9), reg(RBX)))
            .ins(load(reg(RAX), reg(R9)))
            .ins(load(reg(RDX), reg(RAX)))
            .ins(store(reg(R9), reg(R8)))
            .ins(store(reg(RBX), reg(R8))))
    view = _view(_finish(body))
    assert len(_candidates(view)) == 1
    assert _candidates(view) == _candidates(view, RCX)


def test_an_unresolved_alternative_is_not_dropped_to_make_a_unique_capture(engine):
    body = (_main().cbranch("read", reg(ZF, 1)).ins(load(reg(RAX), reg(R9)))
            .ins(store(reg(RBX), reg(RAX))).label("read")
            .ins(load(reg(RDX), reg(RBX))))
    view = _view(_finish(body))
    sink = max(position for position, operation in view.operations.values() if operation.opcode == "CALL")
    backend = _FunctionPhysicalStateBackend(view)
    register = backend.register_span(PhysicalRegisterSlice(RDX, 8))
    definition_id = view.state_definition(register, sink)
    assert definition_id is not None
    paths = view.complete_physical_pointer_candidates(definition_id, register)
    assert {len(path.offsets) for path in paths} == {1, 2}
    # The slot's two captured alternatives must not become a proof of the
    # one pointer that happens to be materializable.
    assert _candidates(view) == ()


def test_captured_pointer_sink_binds_to_the_original_complete_memory_graph(engine):
    body = (FunctionBuilder().sub_rsp(0x38)
            .ins(add(reg(RBX), reg(RSP), const(0x20)))
            .ins(add(reg(R8), reg(RSP), const(0x10)))
            .ins(store(reg(RBX), reg(R8)))
            .ins(store(reg(R8), reg(RCX, 2)))
            .ins(load(reg(RDX), reg(RBX))))
    view = _view(_finish(body))
    sink_key = next(key for key, (_, operation) in view.operations.items() if operation.opcode == "CALL")
    selector = PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), 0, 2)
    (boundary,) = _direct_sink_boundary_nodes(
        view, "consumer.bytes", sink_key, view.position(sink_key), 0, (selector,)
    )
    (definition_id,) = [index for index, definition in enumerate(view.memory.definitions)
                       if definition.span.size == 2 and definition.operation_key is not None
                       and view.operation(definition.operation_key).opcode == "STORE"]
    assert boundary.node == view.memory_graph.definition_nodes[definition_id]
    graph = view.normalized.dependencies
    result = BackwardSliceQuery().run(view.normalized, boundary.node)
    assert result.is_complete
    assert graph.node_for_key("op:" + view.memory.definitions[definition_id].operation_key) in result.reachable_nodes
    assert not view.normalized.assumes_entry_values_not_frame
