"""(P-fix, docs 25.109) A physical context's terminal registers never cross an unexported call write.

``terminal_register`` exports a callee's raw SSA bytes at a terminal. An inner
call whose summary leaves a register "unknown" (no run, not preserved) writes
it without an SSA definition, so the definition reaching the RETURN can be
stale: ``F: rax = 0; call H; ret`` with ``H: rax = [rcx ^ rdx]`` exported
``0`` (the record evaluated to 5, the run to 0x1239). Now a requested span is
exported only when the callee's own exit summary at that block covers it with
runs that cross nothing; otherwise the export is cut, its reason recorded in
``physical_output_cuts`` -- the context stays usable for other exports.
"""

import json
from types import SimpleNamespace

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader, final_register
from synthetic import (
    CONST, RAM, REG, R8, RAX, RBX, RCX, RDX, RSP, ZF, FunctionBuilder, add, const, copy, load, op, reg, store, tmp,
)
from test_physical_call_records import POINTER, STACK, _case, _record

from tdo_v2._record_calls import terminal_register
from tdo_v2._record_memory import evaluate_physical
from tdo_v2.operation_records import Ineligible, _StitchCut
from tdo_v2.span_geometry import ByteSpan

INNER = 0x1a00
UNKNOWN = tmp(0x300)


def _unknown_into(register):
    """``H``: ``register = [rcx ^ rdx]`` -- an address the summary cannot
    export: no run, not preserved."""
    return FunctionBuilder(entry=INNER).ins(op("INT_XOR", [reg(RCX), reg(RDX)], UNKNOWN),
                                            load(reg(register), UNKNOWN)).ret()


def _caller(read=RAX):
    return FunctionBuilder().sub_rsp(0x28).call(0x1800).ins(add(reg(RAX), reg(read), const(5))).add_rsp(0x28).ret()


def _run(case, registers=(), callother=False):
    vm = Interpreter(case["item"].unit.observation, constant_space=CONST, seed=0, program=case["program"],
                     resume_unvalidated_returns=True)
    for offset, contents in ((RSP, STACK), (RCX, POINTER), (RDX, 0x40), *registers):
        vm.preset(REG, offset, 8, contents)
    vm.preset(RAM, STACK, 8, 0x2000)
    vm.preset(RAM, POINTER ^ 0x40, 8, 0x1234)
    run = vm.run()
    assert run.completed
    return vm


def _cuts(record):
    return [row["reason"] for row in record.get("physical_output_cuts", ())]


def test_a_register_written_before_an_unexported_inner_write_is_cut():
    """The reproduced defect: the record no longer evaluates to the stale 5."""
    middle = FunctionBuilder(entry=0x1800).sub_rsp(0x28).ins(copy(reg(RAX), const(0))).call(INNER) \
        .add_rsp(0x28).ret()
    case = _case(_caller(), middle, _unknown_into(RAX))
    record = _record(case, "1:1008:0:INT_ADD")
    assert any(reason.startswith("physical terminal register crosses a call at ") for reason in _cuts(record)), \
        record.get("physical_output_cuts")
    json.loads(json.dumps(record))   # (the diagnostics are JSON rows)
    vm = _run(case)
    assert final_register(vm, RAX, 8) == 0x1239
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(vm))


@pytest.mark.parametrize("reads, reason", [(False, "has no exit run"), (True, "crosses a call")])
def test_an_entry_register_the_inner_call_writes_is_cut(reads, reason):
    """``F`` leaves r8 alone (or only reads it), ``H`` writes r8 unknown: no
    exit run at all, or an ENTRY run crossed by the call."""
    middle = FunctionBuilder(entry=0x1800).sub_rsp(0x28)
    if reads:
        middle.ins(copy(reg(RBX), reg(R8)))
    middle.call(INNER).add_rsp(0x28).ret()
    case = _case(_caller(R8), middle, _unknown_into(R8))
    record = _record(case, "1:1008:0:INT_ADD")
    assert any(reason in row for row in _cuts(record)), record.get("physical_output_cuts")
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(_run(case, registers=((R8, 0x99),))))


def test_an_exported_inner_write_is_trusted():
    """``H`` exports rax (``rdx + 1``): its staged write ends the crossing --
    the record evaluates to the run's value."""
    middle = FunctionBuilder(entry=0x1800).sub_rsp(0x28).ins(copy(reg(RAX), const(0))).call(INNER) \
        .add_rsp(0x28).ret()
    inner = FunctionBuilder(entry=INNER).ins(add(reg(RAX), reg(RDX), const(1))).ret()
    case = _case(_caller(), middle, inner)
    record = _record(case, "1:1008:0:INT_ADD")
    assert not _cuts(record)
    vm = _run(case)
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == 0x46


def test_a_register_restored_after_the_inner_call_is_trusted():
    """push rbx; call H (rbx unknown); pop rbx: the pop's definition reaches the
    RETURN without a crossing -- the caller's rbx read evaluates exactly."""
    middle = (FunctionBuilder(entry=0x1800).push(RBX).sub_rsp(0x20).call(INNER).add_rsp(0x20).pop(RBX).ret())
    case = _case(_caller(RBX), middle, _unknown_into(RBX))
    record = _record(case, "1:1008:0:INT_ADD")
    assert not _cuts(record), record.get("physical_output_cuts")
    vm = _run(case, registers=((RBX, 0x55),))
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == 0x5a


def test_one_crossed_exit_of_several_cuts_the_export():
    """``jz out; call H; ret`` / ``out: ret`` with rax = 0 first: the exits phi
    needs every terminal -- the crossed one cuts it (its block named)."""
    middle = (FunctionBuilder(entry=0x1800).sub_rsp(0x28).ins(copy(reg(RAX), const(0)))
              .cbranch("out", reg(ZF, 1)).call(INNER).add_rsp(0x28).ret()
              .label("out").add_rsp(0x28).ret())
    case = _case(_caller(), middle, _unknown_into(RAX))
    record = _record(case, "1:1008:0:INT_ADD")
    assert any(reason.startswith("physical terminal register crosses a call at 1:18") for reason in _cuts(record)), \
        record.get("physical_output_cuts")


# -- the rule itself, on the exporter (no SSA walk reached when it cuts) -----------------


def _span(start, size):
    from tdo_v2.span_geometry import StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind

    scope = StorageScopeId(StorageScopeKind.PROGRAM, bytes(32))
    return ByteSpan(StorageObjectId(StorageObjectKind.REGISTER_FILE, scope, 0), start, size)


def _builder(*runs, block="1:1810"):
    exit_ = SimpleNamespace(block_key=block, runs=tuple(SimpleNamespace(span=span, crossed=crossed)
                                                        for span, crossed in runs))
    return SimpleNamespace(terminal_exits={block: exit_}, ssa=None)


@pytest.mark.parametrize("builder, reason", [
    (SimpleNamespace(ssa=None), "physical terminal facts unavailable"),
    (_builder(block="1:1900"), "physical terminal exit summary unavailable at 1:1810"),
    (_builder((_span(0, 4), ()), (_span(4, 4), ("call:1:1808:2:CALL",))),
     "physical terminal register crosses a call at 1:1810"),            # (eax trusted, the high half crossed)
    (_builder((_span(0, 4), ())), "physical terminal register has no exit run at 1:1810"),
    (_builder((_span(0, 2), ()), (_span(4, 4), ())), "physical terminal register has no exit run at 1:1810"),
])
def test_the_terminal_rule_cuts_before_reading_any_state(builder, reason):
    with pytest.raises(_StitchCut, match=reason):
        terminal_register(builder, _span(0, 8), "1:1810", "1:1810:1:RETURN")


def test_a_terminal_covered_by_uncrossed_runs_reaches_the_state_walk():
    """Fully covered, nothing crossed: the check passes (the walk then needs a
    real builder -- a missing exit state cuts there)."""
    builder = _builder((_span(0, 4), ()), (_span(4, 4), ()))
    builder.ssa = SimpleNamespace(exit_states=())
    with pytest.raises(_StitchCut, match="physical terminal state unavailable"):
        terminal_register(builder, _span(0, 8), "1:1810", "1:1810:1:RETURN")


# -- review r1 (Fable P1-b / r2 P2-b): an exempted call never vouches for a value -----------


def test_a_no_effect_user_op_between_the_write_and_the_return_refuses_when_it_runs():
    """``rax = 0; CALLOTHER pause; ret`` with ``pause`` declared no-effect: no
    crossing is generated (an intrinsic), so the export is trusted -- but the
    user op is never expanded physically: its event is a call without a
    context, and the evaluator refuses the record on the run that executes it."""
    from test_physical_call_records import OPTIONS

    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.pcodeop_models import PcodeOpModel
    from synthetic import program_units

    middle = FunctionBuilder(entry=0x1800).sub_rsp(0x28).ins(copy(reg(RAX), const(7))) \
        .ins(op("CALLOTHER", [const(0x77, 4)])).add_rsp(0x28).ret()
    units = program_units(_caller(), middle)
    namespace = units[0].scopes.program.evidence.translation_namespace
    pause = PcodeOpModel("pause-model", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                        namespace.minor_version)}), {0x77: "pause"})
    provenance = {}
    results = analyze_units(units, record_provenance=provenance, pcodeop_models=(pause,), **OPTIONS)
    case = dict(item=results["1:1000"], callee=results["1:1800"], results=results, provenance=provenance,
                program={(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset):
                         unit.observation for unit in units})
    record = _record(case, "1:1008:0:INT_ADD")
    assert not _cuts(record), record.get("physical_output_cuts")
    vm = Interpreter(case["item"].unit.observation, constant_space=CONST, seed=0, program=case["program"],
                     resume_unvalidated_returns=True, no_effect_userops=frozenset({0x77}))
    for offset, contents in ((RSP, STACK), (RCX, POINTER), (RDX, 0x40)):
        vm.preset(REG, offset, 8, contents)
    vm.preset(RAM, STACK, 8, 0x2000)
    assert vm.run().completed and final_register(vm, RAX, 8) == 12
    assert any(key.endswith(":CALLOTHER") for key in record.get("physical_call_cuts", {})),         record.get("physical_call_cuts")   # (the user op is never expanded)
    with pytest.raises(Ineligible, match="unknown physical call"):
        evaluate_physical(record, entry_reader(vm))


def test_the_terminal_stack_pointer_gets_the_same_rule():
    """(Fable P1-a) The SP a context's RETURN check reads is exported by the
    same rule: a crossed SP run cuts (no exemption for the RETURN / SP contract)."""
    builder = _builder((_span(RSP, 8), ("call:1:1808:2:CALL",)))
    with pytest.raises(_StitchCut, match="crosses a call"):
        terminal_register(builder, _span(RSP, 8), "1:1810", "1:1810:1:RETURN")


# -- code review r1 (Fable P2-c, Astra P2 / P3) ---------------------------------------------


def test_a_cut_export_leaves_the_contexts_other_exports_usable():
    """``rax = 0; call H; r8 = rdx + 3; ret`` (H leaves rax unknown): rax is
    cut (crossed), r8 (written after the call) still exports from the same
    context; the record renders the cut, and its rows round-trip through JSON."""
    from tdo_v2.operation_records import render

    caller = FunctionBuilder().sub_rsp(0x28).call(0x1800).ins(add(reg(RAX), reg(RAX), reg(R8))).add_rsp(0x28).ret()
    middle = (FunctionBuilder(entry=0x1800).sub_rsp(0x28).ins(copy(reg(RAX), const(0))).call(INNER)
              .ins(add(reg(R8), reg(RDX), const(3))).add_rsp(0x28).ret())
    case = _case(caller, middle, _unknown_into(RAX))
    record = json.loads(json.dumps(_record(case, "1:1008:0:INT_ADD")))
    (row,) = record["physical_output_cuts"]
    assert row["offset"] == RAX and row["size"] == 8 and "crosses a call" in row["reason"]
    outputs = {(item["offset"], item["size"]) for item in record["physical_calls"][row["context"]]["outputs"]}
    assert outputs == {(R8, 8)}, outputs
    assert f"at 0x{RAX:x}+8 not exported" in render(record)


def test_an_indirect_candidate_whose_own_exit_crosses_cuts_the_selection(monkeypatch):
    """Candidate B: ``rax = 0; call H; ret`` (H leaves rax unknown); A is
    plain: the selection's rax export is cut, with the member's own reason
    and the selection's, by its own exits (``terminal_exits`` per member)."""
    from test_indirect_physical_calls import A, B, _callee, _case as _indirect_case, _final

    member = FunctionBuilder(entry=B).sub_rsp(0x28).ins(copy(reg(RAX), const(0))).call(INNER).add_rsp(0x28).ret()
    case = _indirect_case(monkeypatch, a=_callee(A, 1), b=member, extra=(_unknown_into(RAX),))
    record = _final(case)
    reasons = _cuts(record)
    member = [row for row in record["physical_output_cuts"] if "crosses a call" in row["reason"]]
    assert member and all(row["context"].endswith(f"@1:{B:x}") for row in member), record["physical_output_cuts"]
    assert "physical target output unavailable" in reasons, reasons


def test_a_crossed_terminal_stack_pointer_cuts_the_whole_context():
    """(Fable P1-a, integration) The SP the RETURN check reads goes through the
    rule inside ``_context``: a crossed SP run cuts the context itself --
    its reason in ``physical_call_cuts``. (Built by marking the callee's own
    exit SP run crossed: an RET's ``rsp += 8`` follows every call, so a real
    crossed terminal SP needs no call between that write and the exit.)"""
    from dataclasses import replace

    middle = FunctionBuilder(entry=0x1800).sub_rsp(0x28).ins(copy(reg(RAX), const(7))).add_rsp(0x28).ret()
    case = _case(_caller(), middle)
    done = case["callee"]   # (``_case`` analyses afresh per call: no cached result is changed)
    exits = tuple(replace(exit_, runs=tuple(replace(run, crossed=("call:1:1800:0:CALL",))
                                             if run.span.start <= RSP < run.span.end else run for run in exit_.runs))
                  for exit_ in done.summary.exits)
    object.__setattr__(done, "summary", replace(done.summary, exits=exits))
    record = _record(case, "1:1008:0:INT_ADD")
    assert any("crosses a call" in reason for reason in record.get("physical_call_cuts", {}).values()), \
        record.get("physical_call_cuts")


@pytest.mark.parametrize("skips", [True, False])
def test_a_user_op_on_one_path_refuses_only_where_it_runs(skips):
    """``rax = 7; if rcx == 0 goto skip; CALLOTHER pause; skip: ret`` (rcx: no
    instruction of the caller writes it -- flags would be): the path that
    skips the user op evaluates to the run's value; the one through it refuses."""
    from test_physical_call_records import OPTIONS

    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.pcodeop_models import PcodeOpModel
    from synthetic import program_units

    middle = (FunctionBuilder(entry=0x1800).sub_rsp(0x28).ins(copy(reg(RAX), const(7)))
              .cbranch("skip", tmp(0x320, 1), op("INT_EQUAL", [reg(RCX), const(0)], tmp(0x320, 1)))
              .ins(op("CALLOTHER", [const(0x77, 4)])).label("skip").add_rsp(0x28).ret())
    units = program_units(_caller(), middle)
    namespace = units[0].scopes.program.evidence.translation_namespace
    pause = PcodeOpModel("pause-model", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                        namespace.minor_version)}), {0x77: "pause"})
    provenance = {}
    results = analyze_units(units, record_provenance=provenance, pcodeop_models=(pause,), **OPTIONS)
    case = dict(item=results["1:1000"], callee=results["1:1800"], results=results, provenance=provenance,
                program={(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset):
                         unit.observation for unit in units})
    record = _record(case, "1:1008:0:INT_ADD")
    vm = Interpreter(case["item"].unit.observation, constant_space=CONST, seed=0, program=case["program"],
                     resume_unvalidated_returns=True, no_effect_userops=frozenset({0x77}))
    for offset, contents in ((RSP, STACK), (RCX, 0 if skips else POINTER), (RDX, 0x40)):
        vm.preset(REG, offset, 8, contents)
    vm.preset(RAM, STACK, 8, 0x2000)
    assert vm.run().completed and final_register(vm, RAX, 8) == 12
    if skips:
        assert evaluate_physical(record, entry_reader(vm)).value == 12
    else:
        with pytest.raises(Ineligible, match="unknown physical call"):
            evaluate_physical(record, entry_reader(vm))
