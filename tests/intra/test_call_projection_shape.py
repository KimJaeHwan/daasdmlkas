"""The call-state projection (the push of a call shape removed, the callee
entry SP = the caller's + delta) is recognized only when nothing but the
return-address store lies between the push and the call: removing the push
would change the stack pointer such an operation sees, and its memory
accesses may alias the removed store (found in the F2a review, docs 25.33;
Ghidra's x86 calls compute their target before the push)."""

from synthetic import (
    CODE_BASE, RAX, RBX, RCX, RSP, FunctionBuilder, _Instruction, add, const, copy, load, op, program_units, ram, reg,
    store, sub, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.observed_call_state import observed_call_state_projections

CALLEE = CODE_BASE + 0x800


def _shaped(builder, *between, before=()):
    """A call instruction: ``before``; rsp -= 8; [rsp] = return; ``between``; CALL."""
    after = builder._address(len(builder._rows) + 1)
    builder._rows.append(_Instruction([*before, sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(after)),
                                       *between, op("CALL", [ram(CALLEE)])], "call", call_target=CALLEE))
    return builder


def _projected(builder):
    (unit,) = program_units(builder.ret())
    return observed_call_state_projections(unit.observation)


def test_the_plain_call_shape_is_projected():
    assert len(_projected(_shaped(FunctionBuilder().sub_rsp(0x28)))) == 1


def test_a_target_computed_before_the_push_is_still_projected():
    t = tmp(0x400)
    assert len(_projected(_shaped(FunctionBuilder().sub_rsp(0x28), before=(copy(t, reg(RAX)),)))) == 1


def test_a_stack_pointer_read_after_the_push_refuses_the_projection():
    assert _projected(_shaped(FunctionBuilder().sub_rsp(0x28), copy(reg(RCX), reg(RSP)))) == ()


def test_a_stack_pointer_moved_after_the_push_refuses_the_projection():
    assert _projected(_shaped(FunctionBuilder().sub_rsp(0x28), copy(reg(RSP), reg(RAX)))) == ()


def test_a_memory_read_after_the_push_refuses_the_projection():
    """``rax = [rcx]`` between the push and the call, rcx = rsp - 8 set before:
    it reads the return-address slot the push wrote (Astra, projection fix
    round 1) -- no stack-pointer register in it."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(sub(reg(RCX), reg(RSP), const(8)), store(reg(RCX), reg(RBX)))
    assert _projected(_shaped(builder, load(reg(RAX), reg(RCX)))) == ()


def test_a_computation_after_the_push_refuses_the_projection():
    assert _projected(_shaped(FunctionBuilder().sub_rsp(0x28), copy(reg(RAX), const(1)))) == ()


def test_a_far_call_with_two_pushes_is_not_projected():
    """``rsp -= 8; [rsp] = cs; rsp -= 8; [rsp] = ret; CALL`` (lcall): the far
    return pops both -- refusing only the first candidate would project the
    second with delta -8 (Fable, projection fix round 1)."""
    builder = FunctionBuilder().sub_rsp(0x28)
    assert _projected(_shaped(builder, before=(sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(0x33))))) == ()


def test_another_stack_pointer_write_in_the_instruction_refuses_the_projection():
    builder = FunctionBuilder().sub_rsp(0x28)
    assert _projected(_shaped(builder, before=(sub(reg(RSP), reg(RSP), const(2)),))) == ()


def test_the_backward_read_reaches_the_pushed_slot():
    """``[rsp] = rbx`` then the shape with ``rcx = rsp`` after the push, then
    ``LOAD [rcx]``: rcx addresses the return-address slot (-0x30), which the
    push wrote -- not rbx's slot (-0x28) the projection had wired it to
    (Fable, F2a round 3). (The program oracle attributes a call instruction's
    push to the callee's activation, so this shape is checked on the SSA.)"""
    caller = FunctionBuilder().sub_rsp(0x28).ins(store(reg(RSP), reg(RBX)))
    caller = _shaped(caller, copy(reg(RCX), reg(RSP))).ins(load(reg(RAX), reg(RCX)))
    caller = caller.add_rsp(0x28).ret()
    analyzed = analyze_units(program_units(caller, FunctionBuilder(entry=CALLEE).ret()))["1:1000"]
    ssa = analyzed.normalized.memory_ssa
    action = next(index for index, row in enumerate(ssa.actions) if row.operation_key == "1:100c:0:LOAD")
    (read,) = [row for row in ssa.reads if row.action_id == action and row.span.object_id.kind.value != "register_file"]
    assert read.span.start == (1 << 64) - 0x30
    writers = {ssa.definitions[index].operation_key for fragment in read.fragments for index in fragment.definition_ids}
    assert writers == {"1:1008:1:STORE"}   # (the push's return-address store)


def _oracle(units, key="1:1000", pools=None):
    import test_graph_fidelity as fidelity
    from program_oracle import check_program
    from synthetic import REG

    analyzed = analyze_units(units)[key]
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = pools or (lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000})
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=(REG, RSP, 8))
    return analyzed, report


def test_the_oracle_keeps_an_unprojected_push_in_the_caller():
    """The interpreter opens the activation of a call whose push the engine
    keeps (an unprojected shape) at the call operation: the push is the
    caller's write, as in the engine, and the read of the pushed slot checks
    (B2: it used to be attributed to the callee -- 'write outside its run')."""
    caller = FunctionBuilder().sub_rsp(0x28).ins(store(reg(RSP), reg(RBX)))
    caller = _shaped(caller, copy(reg(RCX), reg(RSP))).ins(load(reg(RAX), reg(RCX)))
    caller = caller.add_rsp(0x28).ret()
    _, report = _oracle(program_units(caller, FunctionBuilder(entry=CALLEE).ret()))
    assert report.checked and report.silent == [] and report.covered_by_debt == []


def test_a_recursive_call_with_an_unprojected_push_stays_sound():
    """B1 (a limitation, not a hole): with the push kept as an operation the
    caller has no way to state "the stack pointer is back to its pre-push
    value" (no call shape: no excluded stack pointer, no delta), so the
    recursion rounds do not reach a verified fixpoint and the intra-SCC call
    stays opaque (``recursion_unresolved``) -- every dependency still checks.
    Ghidra's x86 calls are always projected (``observed_call_state``)."""
    import test_graph_fidelity as fidelity

    flag = tmp(0x300, 1)

    def recursive(*between):
        builder = FunctionBuilder().sub_rsp(0x28).cbranch("done", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag)) \
            .ins(sub(reg(RCX), reg(RCX), const(1)))
        after = builder._address(len(builder._rows) + 1)
        builder._rows.append(_Instruction([sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(after)),
                                           *between, op("CALL", [ram(CODE_BASE)])], "call", call_target=CODE_BASE))
        return builder.label("done").add_rsp(0x28).ret()

    # (a small depth: every activation returns, the opaque call's debts are exercised)
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000, RCX: seed}
    unprojected = recursive(copy(reg(RAX), const(1)))
    assert not observed_call_state_projections(program_units(unprojected)[0].observation)
    analyzed, report = _oracle(program_units(unprojected), pools=pools)
    assert analyzed.recursion_unresolved   # (opaque: sound, not precise)
    assert report.checked and report.silent == []
    projected, _ = _oracle(program_units(recursive()), pools=pools)
    assert not projected.recursion_unresolved   # (the projected shape converges)
