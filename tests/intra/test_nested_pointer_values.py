"""Nested same-object pointer values (docs 25.11): a callee's summary says
its result is the same pointer as a register / memory it was passed; the
caller's own summary composes that with its own copies, so a caller of the
caller can still place memory through the result."""

from synthetic import (
    CODE_BASE, R9, RAX, RCX, RDI, RSI, RSP, FunctionBuilder, add, const, copy, load, op, program_units, reg,
    slice_from, store, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.span_geometry import StorageObjectKind

G, F, H = CODE_BASE + 0xC00, CODE_BASE + 0x800, CODE_BASE


def _rax_values(results, entry):
    """The pointer values of the function's rax output runs (every exit)."""
    found = set()
    for exit_summary in results[f"1:{entry:x}"].summary.exits:
        for run in exit_summary.runs:
            if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE and run.span.start == RAX \
                    and run.span.size == 8:
                found.add(run.value)
    return found


def _returns_rcx():
    return FunctionBuilder(entry=G).ins(copy(reg(RAX), reg(RCX))).ret()


def _returns_slot():
    """G: rax = *(rcx) -- the pointer stored at what it was passed."""
    return FunctionBuilder(entry=G).ins(load(reg(RAX), reg(RCX))).ret()


def _passes(argument_ops):
    """F: rcx = <argument>; call G; ret (rax is G's result)."""
    return (FunctionBuilder(entry=F).sub_rsp(0x28)
            .ins(*argument_ops)
            .call(G)
            .add_rsp(0x28).ret())


def test_a_register_value_is_composed():
    results = analyze_units(program_units(_passes([copy(reg(RCX), reg(RDI))]), _returns_rcx()))
    (value,) = _rax_values(results, F)
    assert value is not None and value[0] == "same" and value[1].start == RDI and value[2] is False


def test_a_memory_value_is_composed():
    results = analyze_units(program_units(_passes([copy(reg(RCX), reg(RDI))]), _returns_slot()))
    (value,) = _rax_values(results, F)
    assert value is not None and value[0] == "same" and value[1].object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
    assert value[1].size == 8 and value[2] is False


def test_a_value_that_is_not_a_copy_stays_unknown():
    results = analyze_units(program_units(_passes([add(reg(RCX), reg(RDI), const(8))]), _returns_rcx()))
    assert _rax_values(results, F) == {None}


def test_a_loop_feeding_a_call_its_own_result_terminates():
    """Astra (design round 1): rcx = rdi; loop { rax = G(rcx); rcx = rax }."""
    flag = tmp(0x300, 1)
    looping = (FunctionBuilder(entry=F).sub_rsp(0x28)
               .ins(copy(reg(RCX), reg(RDI)))
               .label("top").call(G)
               .ins(copy(reg(RCX), reg(RAX)))
               .cbranch("top", flag, op("INT_NOTEQUAL", [reg(RSI), const(0)], flag))
               .add_rsp(0x28).ret())
    results = analyze_units(program_units(looping, _returns_rcx()))
    values = _rax_values(results, F)
    assert values <= {None} or all(value[0] == "same" and value[1].start == RDI for value in values)


def _caller():
    """H: *(rdi) = rsi; call F(rdi); r9 = *(rax) (instruction 3)."""
    return (FunctionBuilder(entry=H).sub_rsp(0x28)
            .ins(store(reg(RDI), reg(RSI)))
            .call(F)
            .ins(load(reg(R9), reg(RAX)))
            .add_rsp(0x28).ret())


def _program():
    return program_units(_caller(), _passes([copy(reg(RCX), reg(RDI))]), _returns_rcx())


def test_a_caller_of_the_caller_places_memory_through_the_result():
    """H -> F -> G (returns rcx): rax after the call is H's rdi, so *(rax) is
    *(rdi) = rsi -- exact and complete (before: an unknown pointer, incomplete)."""
    from test_index_addresses import _load_node

    results = analyze_units(_program())
    function = results[f"1:{H:x}"].normalized
    found = slice_from(function, _load_node(function, 3))
    assert set(range(RSI, RSI + 8)) <= found.register_bytes
    # F escapes the stack (its summary), so the CALL's push -- a frame write
    # before it (``normalize._push_row``) -- may be read back through another
    # base afterwards: the read through the result carries that debt only
    # (may_alias's ordinary rule for any frame write; docs 25.73)
    (row,) = [row for row in function.may_alias_reads if row.operation_key.endswith(":LOAD")
              and any(writer.endswith("~push") for writer in row.writers)]
    assert all(writer.endswith("~push") for writer in row.writers)


def test_the_caller_of_the_caller_matches_the_concrete_runs():
    from program_oracle import check_program
    from synthetic import REG

    import test_graph_fidelity as fidelity

    units = _program()
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results[f"1:{H:x}"]
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=(REG, RSP, 8))
    assert report.runs and report.silent == []


def test_exits_returning_different_pointers_give_the_caller_no_value():
    """G returns rcx on one exit and rdx on the other: the merged run at the
    call carries two pointer markers -- no value (Astra, review round 1)."""
    from synthetic import RDX

    flag = tmp(0x300, 1)
    two_exits = (FunctionBuilder(entry=G)
                 .cbranch("other", flag, op("INT_NOTEQUAL", [reg(RSI), const(0)], flag))
                 .ins(copy(reg(RAX), reg(RCX)))
                 .ret()
                 .label("other")
                 .ins(copy(reg(RAX), reg(RDX)))
                 .ret())
    results = analyze_units(program_units(_passes([copy(reg(RCX), reg(RDI))]), two_exits))
    effect = next(effect for key, effect in results[f"1:{F:x}"].proven.items() if key.endswith(":CALL"))
    rax = [run for run in effect.runs if any(span.start == RAX for span in run.writes)]
    assert rax and all(run.value is None for run in rax)
    assert _rax_values(results, F) == {None}


def test_a_hard_debt_on_any_pointer_slot_load_of_the_call_refuses_the_value(monkeypatch):
    """A two-level load reads where an earlier load pointed: a hard debt on
    any <call>~ld row of the call refuses the composed value (agy, design
    round 1) -- checked on the composition itself with a stub tracer."""
    from types import SimpleNamespace

    import tdo_v2.function_summary as summary
    from tdo_v2.function_summary import ExitSummary, SummaryKind, SummaryRun
    from tdo_v2.span_geometry import ByteSpan

    registers = analyze_units(program_units(_returns_rcx()))[f"1:{G:x}"].normalized.memory_ssa.definitions[0] \
        .span.object_id
    entry = ByteSpan(registers, RDI, 8)
    run = SummaryRun(ByteSpan(registers, RAX, 8), SummaryKind.COMPUTED, (0,), ("c~2",), (entry,), (), (), ())
    normalized = SimpleNamespace(pointer_rows=(("c~2", ("mem", "c~ld1", 8, False, True)),),
                                 proven_call_effects=(), fresh_rows=frozenset(), same_object_rows=())
    monkeypatch.setattr(summary, "_pointer_size", lambda normalized: 8)

    def composed(indebted):
        tracer = SimpleNamespace(hard_indebted=frozenset(indebted), origin=lambda definition, span: ("row", "c~2"),
                                 load_origin=lambda reader, size: ("entry", entry),
                                 argument_origin=lambda reader, argument: None)
        (exit_summary,) = summary._pointer_values(normalized, None, [ExitSummary("b", (run,))], tracer)
        return exit_summary.runs[0].value

    assert composed(()) == ("same", entry, False)
    assert composed({"c~ld0"}) is None      # the outer load of a two-level slot
    assert composed({"c~2"}) is None
