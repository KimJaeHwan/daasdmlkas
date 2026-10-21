"""Models of functions that never return (``noreturn``, crt ``abort``): a call
of one, or a jump to its import thunk, ends the path there
(``interprocedural._noreturn_jumps``, ``function_summary``; docs 25.16).
DFB091: libgcc's ``__emutls_get_address`` jumps ``je abort`` -- those were
tail exits and left every call of it opaque."""

import json
from pathlib import Path

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    NO_CALLBACKS, CODE_BASE, RAX, RBX, RCX, REG, RSP, FunctionBuilder, add, const, copy, op, operation_node_at,
    program_units, ram, reg, slice_from, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import ModelError, load_external_models, load_model_file

MODELS = sorted((Path(__file__).resolve().parents[2] / "models" / "external").glob("*.json"))
ABORT = CODE_BASE + 0xE00     # the abort import thunk
CALLER = CODE_BASE + 0x400
HAVOC = (REG, RSP, 8)
FLAG = tmp(0x300, 1)


def _analyze(*functions, models=True):
    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "abort", None, (), ((1, ABORT),)),), (), ())
    return analyze_units(program_units(*functions), image_info=image,
                         external_models=load_external_models(MODELS, "x86:LE:64:default", "win64")
                         if models else None)


class _JumpsToAbort(FunctionBuilder):
    """Rows ``conditional`` / ``unconditional``: their last op jumps to the
    abort thunk -- Ghidra lists the thunk as a flow target."""

    def __init__(self, conditional=(), unconditional=(), falls_out=False, **kwargs):
        super().__init__(**kwargs)
        self.conditional, self.unconditional = set(conditional), set(unconditional)
        self.falls_out = falls_out  # the conditional jump's fall-through leaves the function

    def to_json(self) -> dict:
        raw = super().to_json()
        for index in self.conditional | self.unconditional:
            row = raw["instructions"][index]
            row["flow_targets"] = [self._coordinate(ABORT)]
            row["flow_type"].update(is_flow=True, is_jump=True,
                                    is_conditional=index in self.conditional,
                                    is_unconditional=index in self.unconditional,
                                    has_fallthrough=index in self.conditional)
            if index in self.unconditional:
                row["fallthrough_present"], row["fallthrough"] = False, None
            elif self.falls_out:
                row["fallthrough_present"] = True
                row["fallthrough"] = self._coordinate(self._address(index + 1))
        return raw


def _guarded(**kwargs):
    """rax = rbx unless rcx != 0, then ``je abort`` (row 2); a plain caller-
    visible result otherwise."""
    builder = _JumpsToAbort(conditional={2}, **kwargs).sub_rsp(0x28)
    builder.ins(op("INT_NOTEQUAL", [reg(RCX), const(0)], FLAG))
    builder.ins(op("CBRANCH", [ram(ABORT), FLAG]))
    return builder.ins(copy(reg(RAX), reg(RBX))).add_rsp(0x28).ret()


def _caller():
    """calls the helper at CODE_BASE, then r9 = rax."""
    return (FunctionBuilder(entry=CALLER).sub_rsp(0x28).call(CODE_BASE)
            .ins(copy(reg(0x88), reg(RAX))).add_rsp(0x28).ret())


def _check(results, key, program=()):
    """The oracle on ``key``; ``program``: keys of functions it runs (not
    havocked), with rcx 0 and not 0 (both sides of the helper's ``je abort``)."""
    analyzed = results[key]
    observations = {(1, results[item].unit.scopes.function.entry.byte_offset): results[item].unit.observation
                    for item in program}
    return check_program(analyzed.normalized, analyzed.unit.observation, observations, seeds=range(6),
                         register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000,
                                                      RCX: seed % 2},
                         havoc_calls=HAVOC, externals={(1, ABORT): "abort"})


def test_the_abort_model_loads_with_noreturn():
    entries = {entry.name: entry for path in MODELS for entry in load_model_file(path).entries}
    assert entries["abort"].noreturn and entries["abort"].observes == ()
    assert not entries["strcpy"].noreturn


@pytest.mark.parametrize("entry, problem", [
    ({"registers": [{"write": [0, 8]}], "memory": [], "observes": []}, "rows"),
    ({"registers": [], "memory": [], "noreturn": True}, "observes undeclared"),
    ({"registers": [], "memory": [], "observes": [], "noreturn": 1}, "not a boolean"),
])
def test_a_noreturn_entry_is_validated(tmp_path, entry, problem):
    item = {"name": "f", **NO_CALLBACKS, "other_memory": "preserved", "noreturn": True, **entry}
    raw = {"format_version": 1, "kind": "declared", "id": "t", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64", "stack_pointer": [32, 8],
           "stack_delta": 8, "preserved": [], "entries": [item]}
    path = tmp_path / "t.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ModelError):
        load_model_file(path)


def test_a_conditional_jump_to_abort_is_no_tail_exit():
    results = _analyze(_guarded(), _caller())
    helper = results["1:1000"]
    jump = "1:1008:0:CBRANCH"
    assert helper.summary.tail_exits == () and len(helper.summary.exits) == 1
    assert helper.declared[jump] == "external-model:crt-win64/abort@v7"
    caller = results[f"1:{CALLER:x}"]
    (effect,) = caller.proven.values()  # the helper's summary now applies
    function = caller.normalized
    read = slice_from(function, operation_node_at(function, 2, 0, entry=CALLER))
    assert read.is_complete and RBX in read.register_bytes
    assert _check(results, "1:1000").silent == []
    report = _check(results, f"1:{CALLER:x}", program=("1:1000",))
    assert report.silent == [] and report.through_calls


def test_without_the_model_the_jump_stays_a_tail_exit():
    results = _analyze(_guarded(), _caller(), models=False)
    assert results["1:1000"].summary.tail_exits
    assert not results[f"1:{CALLER:x}"].proven


def test_an_unconditional_jump_to_abort_is_a_dead_exit():
    # rcx != 0: jmp abort (row 4); otherwise rax = rbx; ret
    builder = _JumpsToAbort(unconditional={6}).sub_rsp(0x28)
    builder.cbranch("fail", FLAG, op("INT_NOTEQUAL", [reg(RCX), const(0)], FLAG))
    builder.ins(copy(reg(RAX), reg(RBX))).add_rsp(0x28).ret()
    builder.label("fail").add_rsp(0x28).ins(op("BRANCH", [ram(ABORT)]))
    builder._rows[-1].kind = "return"  # a terminal row (its flow is set in to_json)
    results = _analyze(builder, _caller())
    helper = results["1:1000"]
    assert helper.summary.tail_exits == () and len(helper.summary.exits) == 1
    assert helper.summary.dead_exits
    assert results[f"1:{CALLER:x}"].proven
    report = _check(results, f"1:{CALLER:x}", program=("1:1000",))
    assert report.silent == [] and report.through_calls


def test_an_unconditional_jump_with_another_observed_target_is_not_taken():
    # Ghidra lists a local target too: the jump may continue in the function
    builder = _JumpsToAbort(unconditional={2}).sub_rsp(0x28)
    builder.ins(op("INT_NOTEQUAL", [reg(RCX), const(0)], FLAG))
    builder.ins(op("BRANCH", [ram(ABORT)]))
    builder.label("back").ins(copy(reg(RAX), reg(RBX))).add_rsp(0x28).ret()
    raw_json = builder.to_json

    def to_json():
        raw = raw_json()
        raw["instructions"][2]["flow_targets"].append(builder._coordinate(builder._address(3)))
        return raw

    builder.to_json = to_json
    results = _analyze(builder)
    assert "1:1008:0:BRANCH" not in results["1:1000"].declared
    assert not results["1:1000"].summary.dead_exits


def test_a_conditional_jump_leaving_on_both_edges_keeps_its_tail_exit():
    # the je abort is the last instruction: its fall-through leaves the function too
    builder = _JumpsToAbort(conditional={2}, falls_out=True).sub_rsp(0x28)
    builder.ins(op("INT_NOTEQUAL", [reg(RCX), const(0)], FLAG))
    builder.ins(op("CBRANCH", [ram(ABORT), FLAG]))
    builder._rows[-1].kind = "return"  # the last row (its flow is set in to_json)
    results = _analyze(builder)
    assert "1:1008:0:CBRANCH" not in results["1:1000"].declared
    assert results["1:1000"].summary.tail_exits


SLOT = CODE_BASE + 0x3000  # abort's import slot


class _Rows(FunctionBuilder):
    """Row overrides applied after serialization: index -> function(row, builder)."""

    def __init__(self, overrides, **kwargs):
        super().__init__(**kwargs)
        self.overrides = overrides

    def to_json(self) -> dict:
        raw = super().to_json()
        for index, change in self.overrides.items():
            change(raw["instructions"][index], self)
        return raw


def _terminal_with_local_target(target_row):
    def change(row, builder):
        row["fallthrough_present"], row["fallthrough"] = False, None
        row["flow_targets"] = [builder._coordinate(builder._address(target_row))]
        row["flow_type"].update(is_flow=True, is_jump=True, is_terminal=True, is_unconditional=True,
                                has_fallthrough=False)
    return change


def _analyze_with_slot(*functions):
    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "abort", None, ((1, SLOT),), ((1, ABORT),)),),
                      (), ())
    return analyze_units(program_units(*functions), image_info=image,
                         external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))


def _reachable_only_through_the_jump(jump):
    """row 1 jumps (``jump``); Ghidra also lists row 2 as its target -- the
    only way to the return."""
    builder = _Rows({1: _terminal_with_local_target(2)}).sub_rsp(0x28)
    builder.ins(jump)
    builder._rows[-1].kind = "return"  # a terminal row (its flow is set in to_json)
    return builder.ins(copy(reg(RAX), reg(RBX))).add_rsp(0x28).ret()


def test_an_import_slot_jump_with_another_observed_target_keeps_its_return():
    results = _analyze_with_slot(_reachable_only_through_the_jump(op("BRANCHIND", [ram(SLOT)])), _caller())
    helper = results["1:1000"]
    assert "1:1004:0:BRANCHIND" not in helper.proven
    assert not any(effect.noreturn for effect in results[f"1:{CALLER:x}"].proven.values())


def test_a_jump_to_an_abort_thunk_function_with_another_observed_target_keeps_its_return():
    thunk = _Rows({0: lambda row, builder: row.update(fallthrough_present=False, fallthrough=None)},
                  entry=ABORT).ins(op("BRANCHIND", [ram(SLOT)]))
    thunk._rows[-1].kind = "return"
    results = _analyze_with_slot(_reachable_only_through_the_jump(op("BRANCH", [ram(ABORT)])), thunk, _caller())
    helper = results["1:1000"]
    assert "1:1004:0:BRANCH" not in helper.proven
    assert not any(effect.noreturn for effect in results[f"1:{CALLER:x}"].proven.values())


def _terminal_with_outside_target(outside):
    def change(row, builder):
        row["fallthrough_present"], row["fallthrough"] = False, None
        row["flow_targets"] = [builder._coordinate(outside)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_terminal=True, is_unconditional=True,
                                has_fallthrough=False)
    return change


RETURNING = CODE_BASE + 0x600  # another function that returns


def _jump_also_listing_a_returning_function(jump):
    builder = _Rows({1: _terminal_with_outside_target(RETURNING)}).sub_rsp(0x28)
    builder.ins(jump)
    builder._rows[-1].kind = "return"
    return builder


def test_an_import_slot_jump_also_listing_another_function_is_not_noreturn():
    returning = FunctionBuilder(entry=RETURNING).ins(copy(reg(RAX), reg(RBX))).ret()
    results = _analyze_with_slot(_jump_also_listing_a_returning_function(op("BRANCHIND", [ram(SLOT)])),
                                 returning, _caller())
    assert "1:1004:0:BRANCHIND" not in results["1:1000"].proven
    assert not any(effect.noreturn for effect in results[f"1:{CALLER:x}"].proven.values())


def test_a_jump_to_an_abort_thunk_function_also_listing_another_function_is_not_noreturn():
    thunk = _Rows({0: lambda row, builder: row.update(fallthrough_present=False, fallthrough=None)},
                  entry=ABORT).ins(op("BRANCHIND", [ram(SLOT)]))
    thunk._rows[-1].kind = "return"
    returning = FunctionBuilder(entry=RETURNING).ins(copy(reg(RAX), reg(RBX))).ret()
    jump = _jump_also_listing_a_returning_function(op("BRANCH", [ram(ABORT)]))
    original = jump.overrides[1]

    def both(row, builder):  # the thunk and the returning function
        original(row, builder)
        row["flow_targets"] = [builder._coordinate(ABORT), builder._coordinate(RETURNING)]
    jump.overrides[1] = both
    results = _analyze_with_slot(jump, thunk, returning, _caller())
    assert "1:1004:0:BRANCH" not in results["1:1000"].proven
    assert not any(effect.noreturn for effect in results[f"1:{CALLER:x}"].proven.values())
