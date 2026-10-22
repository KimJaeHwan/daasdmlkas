"""The p-code interpreter enters a CALLIND into a program function whatever
computes its operand before the push -- ``call r`` (COPY t <- r) and ``call
[m]`` (t = LOAD m, e.g. a table on the stack indexed by a register): docs 25.33
F1b, the oracle multi-target calls are checked against."""

from pcode_interpreter import Interpreter
from synthetic import (
    CODE_BASE, CONST, RAX, RBX, REG, RSP, FunctionBuilder, _Instruction, add, const, copy, load, op, program_units,
    reg, store, sub, tmp,
)

A, B = CODE_BASE + 0x800, CODE_BASE + 0x900


def _table_caller(index):
    """[rsp+0x20] = A; [rsp+0x28] = B; rbx = ``index``; call [rsp+0x20+rbx*8]."""
    t, u = tmp(0x100), tmp(0x180)
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(t, reg(RSP), const(0x20)), store(t, const(A)), add(u, reg(RSP), const(0x28)), store(u, const(B)))
               .ins(copy(reg(RBX), const(index))))
    after = builder._address(len(builder._rows) + 1)
    target, address = tmp(0x400), tmp(0x300)
    builder._rows.append(_Instruction([
        op("INT_MULT", [reg(RBX), const(8)], address), add(address, address, reg(RSP)),
        add(address, address, const(0x20)), load(target, address),
        sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(after)), op("CALLIND", [target]),
    ], "callind"))
    return builder.add_rsp(0x48).ret()


def _run(index):
    callees = (FunctionBuilder(entry=A).ins(copy(reg(RAX), const(1))).ret(),
               FunctionBuilder(entry=B).ins(copy(reg(RAX), const(2))).ret())
    units = program_units(_table_caller(index), *callees)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    interpreter = Interpreter(units[0].observation, constant_space=CONST, seed=0, program=program)
    interpreter.preset(REG, RSP, 8, 0x7000_0000)
    run = interpreter.run()
    return run, interpreter


def test_a_call_through_a_stack_table_enters_the_chosen_function():
    for index, (entry, value) in enumerate(((A, 1), (B, 2))):
        run, interpreter = _run(index)
        assert run.completed
        assert any(key.startswith(f"1:{entry:x}:") for key in run.executed)
        assert interpreter._peek(REG, RAX, 8)[0] == value


def _shaped(*before):
    """A call instruction: ``before``; push; CALLIND t (t = tmp 0x400)."""
    builder = FunctionBuilder()
    after = builder._address(1)
    builder._rows.append(_Instruction([*before, sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(after)),
                                       op("CALLIND", [tmp(0x400)])], "callind"))
    return builder.ret()


def _enters(builder, memory=()):
    callee = FunctionBuilder(entry=A).ins(copy(reg(RAX), const(1))).ret()
    units = program_units(builder, callee)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    interpreter = Interpreter(units[0].observation, constant_space=CONST, seed=0, program=program,
                              havoc_calls=(REG, RSP, 8))
    interpreter.preset(REG, RSP, 8, 0x7000_0000)
    for space, address, value in memory:
        interpreter.preset(space, address, 8, value)
    run = interpreter.run()
    return any(key.startswith(f"1:{A:x}:") for key in run.executed)


def test_a_temporary_overwritten_in_part_is_read_byte_by_byte():
    """(Astra) ``t:8 = A; t:1 = 0x44`` -- the operand is A with its low byte
    replaced: not the program function A."""
    assert _enters(_shaped(copy(tmp(0x400), const(A))))
    assert not _enters(_shaped(copy(tmp(0x400), const(A)), copy(tmp(0x400, 1), const(0x44, 1))))


def test_a_branch_inside_the_call_instruction_is_not_pre_evaluated():
    """(Astra) a branch before the call: the operations taken are not known
    before the instruction runs -- no activation (the call runs as an
    unknown one)."""
    assert not _enters(_shaped(copy(tmp(0x400), const(A)), op("BRANCH", [const(1)])))


def test_a_call_through_a_global_slot_enters_its_function():
    """(Fable) ``call [g]``: COPY t <- ram:g; the slot holds A."""
    from synthetic import ram

    slot = CODE_BASE + 0xF00
    assert _enters(_shaped(copy(tmp(0x400), ram(slot))), memory=((1, slot, A),))


def test_an_assumed_boundary_call_is_not_pre_evaluated():
    """(Astra) the CALLIND's own key is an assumed boundary: ``_execute`` runs
    the assumption, so no activation may be pushed for it."""
    builder = _shaped(copy(tmp(0x400), const(A)))
    callee = FunctionBuilder(entry=A).ins(copy(reg(RAX), const(1))).ret()
    units = program_units(builder, callee)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    call = next(f"1:{row.address.byte_offset:x}:{index}:CALLIND" for row in units[0].observation.instructions
                for index, operation in enumerate(row.operations) if operation.opcode == "CALLIND")
    interpreter = Interpreter(units[0].observation, constant_space=CONST, seed=0, program=program,
                              havoc_calls=(REG, RSP, 8))
    interpreter._assumed = {call: ((), ())}
    interpreter.preset(REG, RSP, 8, 0x7000_0000)
    run = interpreter.run()
    assert run.completed and not any(key.startswith(f"1:{A:x}:") for key in run.executed)


def test_recursion_through_the_same_site_checks_its_own_push():
    """(Fable) F calls table[rbx] after rbx += 1: the outer call enters F, the
    inner one goes to a non-program address -- it is no program call (no push),
    although the stack top is the outer activation of the same call key."""
    t, u = tmp(0x100), tmp(0x180)
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(t, reg(RSP), const(0x20)), store(t, const(CODE_BASE)),
                    add(u, reg(RSP), const(0x28)), store(u, const(0x1234)))
               .ins(add(reg(RBX), reg(RBX), const(1))))
    after = builder._address(len(builder._rows) + 1)
    target, address = tmp(0x400), tmp(0x300)
    builder._rows.append(_Instruction([
        op("INT_MULT", [reg(RBX), const(8)], address), add(address, address, reg(RSP)),
        add(address, address, const(0x20)), load(target, address),
        sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(after)), op("CALLIND", [target]),
    ], "callind"))
    builder = builder.add_rsp(0x48).ret()
    units = program_units(builder)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    interpreter = Interpreter(units[0].observation, constant_space=CONST, seed=0, program=program,
                              havoc_calls=(REG, RSP, 8))
    interpreter.preset(REG, RSP, 8, 0x7000_0000)
    interpreter.preset(REG, RBX, 8, (1 << 64) - 1)
    run = interpreter.run()
    assert run.completed
    entries = [key for key in run.executed if key.startswith(f"1:{CODE_BASE:x}:")]
    assert len(entries) >= 2 * len(units[0].observation.instructions[0].operations)   # (F ran twice)
