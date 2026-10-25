"""Raw access ranges may not contradict a retained entry-frame premise."""

import pytest

from synthetic import (RBX, RCX, RDX, RSP, FunctionBuilder, add, const, copy,
                       load, program_units, reg, store, tmp)
from test_call_activation_lifetime import _clobbered, _key, _read, models
from test_external_models import THUNKS, _image
from tdo_v2._activation_entry import ActivationEntry
from tdo_v2._call_activation import _frame_compatible, _inputs, _normalize
from tdo_v2.forward import probe
from tdo_v2.interprocedural import _relative_anchors, analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def mode(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)


def _case(delta, extra):
    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(add(reg(RCX), reg(RSP), const(delta - 8)), store(reg(RCX), const(0))))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x80).ret()
    callee = (FunctionBuilder(0x1600).sub_rsp(0x38)
              .ins(copy(reg(RBX), reg(RCX)))
              .ins(add(tmp(0x100), reg(RSP), const(0x30)), store(tmp(0x100), reg(RBX))))
    saved = "1:1608:1:STORE"
    target = None
    if extra is not None:
        displacement, width = extra
        target = _key(callee, 1, "LOAD")
        # An unused raw LOAD changes no pointer or source value. It only
        # exposes the range whose original and activation anchors differ.
        callee.ins(add(tmp(0x200), reg(RBX), const(displacement % (1 << 64))),
                   load(tmp(0x300, width), tmp(0x200)))
    old = _key(callee, 0, "LOAD")
    callee.ins(load(reg(RCX), reg(RBX))).ins(copy(reg(RDX), const(16)))
    realloc = _key(callee, 2, "CALL")
    callee.call(THUNKS["realloc"])
    reader = _key(callee, 1, "LOAD")
    callee.ins(add(tmp(0x100), reg(RSP), const(0x30)), load(reg(RBX), tmp(0x100)))
    callee.add_rsp(0x38).ret()
    return program_units(caller, callee), dict(outer=outer, saved=saved, realloc=realloc,
                                             reader=reader, target=target or old)


@pytest.mark.parametrize("delta,extra,compatible", (
    (24, None, False),          # the pointer itself enters the 40-byte home area
    (56, (-64, 8), False),     # an outside pointer reaches SP-8, the saved slot
    (56, (-24, 16), False),    # [SP+32,SP+48) crosses the home boundary at 40
    (56, None, True),          # independent outside-frame control
))
def test_original_ranges_bound_frame_on_activation_without_restricting_frame_off(
        models, delta, extra, compatible):
    units, points = _case(delta, extra)
    for frame in (False, True):
        result = analyze_units(units, image_info=_image(), external_models=models,
                               private_frame_above=40, assume_globals_disjoint_from_stack=True,
                               assume_entry_values_not_frame=frame,
                               assume_opaque_callees_leave_no_stack_addresses=False)
        caller, generic = result["1:1000"], result["1:1600"]
        assert _clobbered(generic, points) and generic.normalized.activation_entry is None
        context = caller.activations.get(points["outer"])
        original = caller if context is None else context.activation_witness[0]
        bound = _inputs(original, generic, points["outer"], (), None)
        assert bound is not None
        sp, _, _, _, relations, labels = bound
        assert any(destination.start == RCX and difference == delta
                   for destination, _, difference in relations)
        state = ActivationEntry(generic.unit.scopes.function.scope,
                                (caller.key, points["outer"]), relations, (), labels)
        mapped = _normalize(generic, state)
        old = _read(generic, points["target"])
        # _read only needs the normalized field; no surrogate SSA is built.
        mapped_read = next(read for read in mapped.memory_ssa.reads
                           if mapped.memory_ssa.actions[read.action_id].operation_key == points["target"]
                           and read.span.object_id.kind == old.span.object_id.kind)
        displacement, width = (0, 8) if extra is None else extra
        assert old.span.start == (1 << 64) + displacement and old.span.size == width
        assert generic.anchors[old.span.object_id][0].start == RCX
        assert mapped_read.span.start == (1 << 64) + delta + displacement
        assert mapped_read.span.size == width and old.span.object_id != mapped_read.span.object_id
        assert _relative_anchors(generic.unit, mapped)[mapped_read.span.object_id] == (sp, 1)
        assert _frame_compatible(generic, mapped, sp, relations) is (compatible or not frame)
        if frame and not compatible:
            assert context is None and not caller.activations
        else:
            assert context is not None and not _clobbered(context, points)
            saved = _read(context, points["reader"])
            ids, _ = probe(context.normalized, points["reader"], (saved.span,))
            definition = context.normalized.memory_ssa.definitions[ids[saved.span]]
            assert definition.kind is MemoryDefinitionKind.DATA_WRITE
            assert definition.operation_key == points["saved"]
            assert not context.proven[points["realloc"]].preserves_memory
