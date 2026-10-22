"""Indirect calls proven (by forward facts) to reach one of several program
functions take the composed effect of their targets (docs 25.33 F1b,
``call_summary_effects.derive_composed_call_effect``): only with the forward
switch on; every member's exits, per-member inner-call clobbers, contested
memory as unknown places; an opaque member, a failed one or one in the
caller's SCC leaves the call opaque."""

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, RAX, RBX, RCX, REG, RSP, FunctionBuilder, add, const, copy, load, op, program_units, reg, store, tmp,
)
from tdo_v2.interprocedural import analyze_units

ROOT = "1:1000"
A, B, OPAQUE = CODE_BASE + 0x800, CODE_BASE + 0x900, CODE_BASE + 0xC00
HAVOC = (REG, RSP, 8)


def _table():
    """[rsp+0x20] = A; [rsp+0x28] = B; i = rcx & 1; call [rsp+0x20+i*8]; rbx = rax."""
    t, u, i = tmp(0x100), tmp(0x180), tmp(0x200)
    return (FunctionBuilder().sub_rsp(0x48)
            .ins(add(t, reg(RSP), const(0x20)), store(t, const(A)), add(u, reg(RSP), const(0x28)), store(u, const(B)))
            .ins(op("INT_AND", [reg(RCX), const(1)], i), op("INT_MULT", [i, const(8)], i),
                 add(i, i, reg(RSP)), add(i, i, const(0x20)), load(reg(RAX), i))
            .call_indirect(RAX).ins(copy(reg(RBX), reg(RAX))).add_rsp(0x48).ret())


def _returns(entry, value):
    return FunctionBuilder(entry=entry).ins(copy(reg(RAX), const(value))).ret()


def _analyze(monkeypatch, *functions, forward=True):
    if forward:
        monkeypatch.setenv("TDO_V2_FORWARD", "1")
    else:
        monkeypatch.delenv("TDO_V2_FORWARD", raising=False)
    units = program_units(*functions)
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    return results, program


def _call(item):
    return next(key for key in item.proven if key.endswith(":CALLIND")) if any(
        key.endswith(":CALLIND") for key in item.proven) else None


def _forward_members(item):
    """The CALLIND's forward target set (so an opaque call is the member rule's doing)."""
    from tdo_v2.interprocedural import _forward_targets

    found, _ = _forward_targets(item, {f"1:{entry:x}" for entry in (A, B, CODE_BASE)}, None)
    return next(iter(found.values()), None)


def _holds(results, program, key=ROOT):
    item = results[key]
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=HAVOC)
    assert report.silent == [], report.silent[:3]
    return report


def test_a_two_target_table_call_composes_both_targets(monkeypatch):
    results, program = _analyze(monkeypatch, _table(), _returns(A, 1), _returns(B, 2))
    item = results[ROOT]
    call = _call(item)
    assert call is not None and item.multi_calls == {call: ("1:1800", "1:1900")}
    effect = item.proven[call]
    assert effect.restores_stack and not effect.noreturn
    written = {span.start for run in effect.runs for span in run.writes}
    assert RAX in written
    assert _holds(results, program).through_calls


def test_forward_off_leaves_the_call_opaque(monkeypatch):
    results, _ = _analyze(monkeypatch, _table(), _returns(A, 1), _returns(B, 2), forward=False)
    assert _call(results[ROOT]) is None and results[ROOT].multi_calls == {}


def test_different_stack_deltas_do_not_restore(monkeypatch):
    popping = FunctionBuilder(entry=B).ins(copy(reg(RAX), const(2))).add_rsp(8).ret()
    results, _ = _analyze(monkeypatch, _table(), _returns(A, 1), popping)
    effect = results[ROOT].proven.get(_call(results[ROOT]) or "", None)
    assert effect is not None and not effect.restores_stack


def test_an_inner_call_of_one_member_clobbers_what_the_other_writes(monkeypatch):
    """A writes rax; B leaves rax to an opaque call: rax is unknown after the
    composed call (not one of A's sources only)."""
    clobbering = FunctionBuilder(entry=B).sub_rsp(0x28).call(OPAQUE).add_rsp(0x28).ret()
    results, program = _analyze(monkeypatch, _table(), _returns(A, 1), clobbering)
    item = results[ROOT]
    effect = item.proven[_call(item)]
    assert not any(span.start <= RAX < span.end for span in effect.preserved)
    assert not any(span.start <= RAX < span.end for run in effect.runs for span in run.writes)
    _holds(results, program)


def test_two_members_writing_memory_leave_unknown_places(monkeypatch):
    """A writes [rdx] = 1, B writes [rdx] = 2 -- different callee objects for
    one caller place: no memory runs, unknown memory at the place."""
    from synthetic import RDX

    a = FunctionBuilder(entry=A).ins(store(reg(RDX), const(1))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), const(2))).ret()
    results, program = _analyze(monkeypatch, _table(), a, b)
    item = results[ROOT]
    effect = item.proven[_call(item)]
    assert not effect.memory_runs and effect.unknown_memory
    _holds(results, program)


def test_a_member_with_no_exit_leaves_the_call_opaque(monkeypatch):
    """B leaves by a tail jump out of the program (a tail exit, no effect of
    its own): the composed call must not become A's effect alone."""
    leaving = FunctionBuilder(entry=B).tail_call(CODE_BASE + 0xE00)
    results, _ = _analyze(monkeypatch, _table(), _returns(A, 1), leaving)
    assert results["1:1900"].summary is not None and results["1:1900"].summary.tail_exits
    assert _forward_members(results[ROOT]) == ("1:1800", "1:1900")
    assert _call(results[ROOT]) is None


def test_a_member_in_the_callers_scc_leaves_the_call_opaque(monkeypatch):
    recursive = FunctionBuilder(entry=B).sub_rsp(0x28).call(CODE_BASE).add_rsp(0x28).ret()
    results, _ = _analyze(monkeypatch, _table(), _returns(A, 1), recursive)
    assert _forward_members(results[ROOT]) == ("1:1800", "1:1900")
    assert _call(results[ROOT]) is None


def test_an_opaque_member_keeps_the_other_members_sinks():
    """(Astra) A passes rcx to a sink; B leaves by a tail exit: the composed
    call proves no state, but A's sink demand still binds at the call."""
    from tdo_v2.call_summary_effects import derive_composed_call_effect
    from tdo_v2.function_summary import FUNCTION_SUMMARY_VERSION, ExitSummary, FunctionSummary, SinkDemand
    from tdo_v2.span_geometry import ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind

    registers = StorageObjectId(StorageObjectKind.REGISTER_FILE, StorageScopeId(StorageScopeKind.PROGRAM, bytes(32)), 0)
    sink = SinkDemand("sink:test", (ByteSpan(registers, RCX, 8),), (), (), True)
    a = FunctionSummary(FUNCTION_SUMMARY_VERSION, (ExitSummary("a", ()),), (), (), sink_demands=(sink,),
                        stack_values_out=False)
    b = FunctionSummary(FUNCTION_SUMMARY_VERSION, (), (), (), tail_exits=("b",), stack_values_out=False)
    effect = derive_composed_call_effect(((a, {}), (b, {})), "targets:a|b", registers, 0x100)
    assert effect is not None and not effect.runs and not effect.preserved
    assert [demand.label for demand in effect.sink_demands] == ["sink:test"]
    assert derive_composed_call_effect(((b, {}), (b, {})), "targets:b|b", registers, 0x100) is None
    # a member with no exit at all (and no dead exit) is opaque too, not dropped
    silent = FunctionSummary(FUNCTION_SUMMARY_VERSION, (), (), (), stack_values_out=False)
    effect = derive_composed_call_effect(((a, {}), (silent, {})), "targets:a|c", registers, 0x100)
    assert effect is not None and not effect.preserved and len(effect.sink_demands) == 1


def test_a_label_an_early_resolution_rested_on_is_kept(monkeypatch):
    """The resolutions of every round count: a label the first round's fact
    needed stays in the caller's inherited assumptions although later rounds'
    facts no longer list it (Astra F1b round 2)."""
    import tdo_v2.interprocedural as interprocedural

    real = interprocedural._forward_targets
    rounds = []

    def forward_targets(item, functions, readonly_image):
        found, labels = real(item, functions, readonly_image)
        if item.key != ROOT:
            return found, labels
        rounds.append(dict(found))
        first = len(rounds) == 1
        return found, {call: frozenset({"early-round-label"}) if first else frozenset() for call in found}

    monkeypatch.setattr(interprocedural, "_forward_targets", forward_targets)
    results, _ = _analyze(monkeypatch, _table(), _returns(A, 1), _returns(B, 2))
    assert len(rounds) >= 2 and _call(results[ROOT]) is not None
    assert "early-round-label" in results[ROOT].inherited_assumptions
