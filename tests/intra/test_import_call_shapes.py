"""Import call shapes (``interprocedural.import_call_sites``): besides ``call
[__imp_X]``, ``mov rax, [__imp_X]; call rax`` -- the debug build of the 09
testbed calls its import DLL this way (docs 25.13) -- when nothing else can
reach the call with another rax."""

from synthetic import (
    CODE_BASE, RAX, RCX, RSP, FunctionBuilder, add, const, copy, op, program_units, ram, reg, store, sub, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import import_call_sites
from tdo_v2.pcode_blocks import build_pcode_block_graph

SLOT = CODE_BASE + 0x3000


def _sites(builder):
    (unit,) = program_units(builder)
    info = ImageInfo("synthetic", (), (ImportedSymbol("LIB.DLL", "f", None, ((1, SLOT),), ()),), (), ())
    return {key: symbol.name for key, symbol in import_call_sites(unit, info).items()}


def test_a_register_loaded_from_the_slot_by_the_previous_instruction_is_the_import():
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)))
               .call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert list(_sites(builder).values()) == ["f"]


def test_a_branch_into_the_call_keeps_it_opaque():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().sub_rsp(0x28)
               .cbranch("call", flag, op("INT_NOTEQUAL", [reg(RCX), const(0)], flag))
               .ins(copy(reg(RAX), ram(SLOT)))
               .label("call").call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


def test_a_later_write_of_part_of_the_register_keeps_it_opaque():
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)), add(reg(RAX, 4), reg(RAX, 4), const(1, 4)))
               .call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


def test_a_load_two_instructions_back_is_not_taken():
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)))
               .ins(copy(reg(RCX), const(1)))
               .call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


def test_a_call_after_the_load_keeps_it_opaque():
    # a call may change rax without naming it as an output
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)), op("CALLOTHER", [const(1, 4)]))
               .call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


def test_a_branch_inside_the_loading_instruction_around_the_load_keeps_it_opaque():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(op("INT_NOTEQUAL", [reg(RCX), const(0)], flag), op("CBRANCH", [const(2, 4), flag]),
                    copy(reg(RAX), ram(SLOT)), copy(reg(RCX), const(1)))
               .call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


def test_a_copied_target_overwritten_before_the_call_keeps_it_opaque():
    target = tmp(0x400)
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)))
               .ins(copy(target, reg(RAX)), copy(target, reg(RCX)), op("CALLIND", [target]))
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


def test_the_register_itself_as_the_target_is_the_import():
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)))
               .ins(op("CALLIND", [reg(RAX)]))
               .add_rsp(0x28).ret())
    assert list(_sites(builder).values()) == ["f"]


def test_a_call_at_the_function_entry_is_not_taken():
    builder = FunctionBuilder().call_indirect(RAX).ret()
    assert _sites(builder) == {}


def test_a_loop_back_into_the_call_keeps_it_opaque():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)))
               .label("call").call_indirect(RAX)
               .cbranch("call", flag, op("INT_NOTEQUAL", [reg(RCX), const(0)], flag))
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


def test_a_memory_target_overwritten_by_a_store_keeps_it_opaque():
    # COPY rax -> M; STORE rcx -> M; CALLIND M: the STORE names no output
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)))
               .ins(copy(ram(SLOT + 0x100), reg(RAX)), store(const(SLOT + 0x100), reg(RCX)),
                    op("CALLIND", [ram(SLOT + 0x100)]))
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


class _WithLandingPad(FunctionBuilder):
    """Gives instruction ``row`` (a call) an exceptional flow target ``label``."""

    def __init__(self, row: int, label: str):
        super().__init__()
        self.pad_row, self.pad_label = row, label

    def to_json(self) -> dict:
        raw = super().to_json()
        target = self._coordinate(self._address(self._labels[self.pad_label]))
        raw["instructions"][self.pad_row]["flow_targets"].append(target)
        return raw


def _split_call_with_landing_pad():
    # row 1: an internal CBRANCH, then a call whose landing pad is the call rax
    flag = tmp(0x300, 1)
    builder = _WithLandingPad(1, "pad").sub_rsp(0x28).call(CODE_BASE + 0x800)
    builder._rows[-1].ops[:0] = [op("INT_NOTEQUAL", [reg(RCX), const(0)], flag),
                                 op("CBRANCH", [const(2, 4), flag]), copy(reg(RCX), const(1))]
    return (builder.ins(copy(reg(RAX), ram(SLOT)))
            .label("pad").call_indirect(RAX)
            .add_rsp(0x28).ret())


def test_a_split_call_with_a_landing_pad_is_unsupported():
    # where in the instruction the exception leaves is not modelled
    (unit,) = program_units(_split_call_with_landing_pad())
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    assert graph.unsupported is not None


def test_a_landing_pad_reached_from_a_split_call_keeps_it_opaque():
    assert _sites(_split_call_with_landing_pad()) == {}


def _graph(builder):
    (unit,) = program_units(builder)
    return build_pcode_block_graph(unit.observation, unit.scopes.function.entry)


def test_a_call_with_a_landing_pad_and_operations_after_it_is_unsupported():
    # CALL; COPY rax <- [slot] in one instruction, landing pad = the call rax:
    # an exception reaches it before the COPY runs
    builder = _WithLandingPad(1, "pad").sub_rsp(0x28).call(CODE_BASE + 0x800)
    builder._rows[-1].ops.append(copy(reg(RAX), ram(SLOT)))
    builder = builder.ins(copy(reg(RCX), const(1))).label("pad").call_indirect(RAX).add_rsp(0x28).ret()
    assert _graph(builder).unsupported is not None
    assert _sites(builder) == {}


class _WithOverride(FunctionBuilder):
    """Gives instruction ``row`` an extra flow target ``label`` (a flow
    override; ``marked``: also flagged ``is_override``)."""

    def __init__(self, row: int, label: str, marked: bool = False):
        super().__init__()
        self.row, self.target_label, self.marked = row, label, marked

    def to_json(self) -> dict:
        raw = super().to_json()
        raw["instructions"][self.row]["flow_targets"].append(
            self._coordinate(self._address(self._labels[self.target_label])))
        if self.marked:
            raw["instructions"][self.row]["flow_type"]["is_override"] = True
        return raw


def test_a_split_instruction_with_a_target_its_branches_do_not_place_is_unsupported():
    flag = tmp(0x300, 1)
    builder = (_WithOverride(1, "pad").sub_rsp(0x28)
               .ins(op("INT_NOTEQUAL", [reg(RCX), const(0)], flag), op("CBRANCH", [const(2, 4), flag]),
                    copy(reg(RCX), const(1)), copy(reg(RCX), const(2)))
               .ins(copy(reg(RAX), ram(SLOT)))
               .label("pad").call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _graph(builder).unsupported is not None
    assert _sites(builder) == {}


def test_a_landing_pad_that_is_also_the_fallthrough_still_counts():
    # CALL; COPY rax <- [slot], and the call rax right after is also listed
    # as the call's landing pad: an exception reaches it before the COPY
    builder = _WithLandingPad(1, "pad").sub_rsp(0x28).call(CODE_BASE + 0x800)
    builder._rows[-1].ops.append(copy(reg(RAX), ram(SLOT)))
    builder = builder.label("pad").call_indirect(RAX).add_rsp(0x28).ret()
    assert _graph(builder).unsupported is not None
    assert _sites(builder) == {}


def test_an_override_placed_only_by_an_unreachable_branch_is_unsupported():
    # BRANCH +2 skips the BRANCH to the call rax: that branch never runs
    pad = CODE_BASE + 3 * 4
    builder = (_WithOverride(1, "pad").sub_rsp(0x28)
               .ins(op("BRANCH", [const(2, 4)]), op("BRANCH", [ram(pad)]), copy(reg(RCX), const(1)))
               .ins(copy(reg(RAX), ram(SLOT)))
               .label("pad").call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _graph(builder).unsupported is not None
    assert _sites(builder) == {}


def test_a_landing_pad_on_a_call_instruction_without_a_call_operation_is_unsupported():
    # CALLOTHER; COPY rax <- [slot] flagged as a call with a landing pad
    builder = _WithLandingPad(1, "pad").sub_rsp(0x28).call(CODE_BASE + 0x800)
    builder._rows[-1].ops[:] = [op("CALLOTHER", [const(1, 4)]), copy(reg(RAX), ram(SLOT))]
    builder = builder.ins(copy(reg(RCX), const(1))).label("pad").call_indirect(RAX).add_rsp(0x28).ret()
    assert _graph(builder).unsupported is not None
    assert _sites(builder) == {}


def test_a_split_instruction_with_an_override_onto_its_fallthrough_is_unsupported():
    flag = tmp(0x300, 1)
    builder = (_WithOverride(1, "pad", marked=True).sub_rsp(0x28)
               .ins(op("INT_NOTEQUAL", [reg(RCX), const(0)], flag), op("CBRANCH", [const(2, 4), flag]),
                    copy(reg(RCX), const(1)), copy(reg(RAX), ram(SLOT)))
               .label("pad").call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _graph(builder).unsupported is not None
    assert _sites(builder) == {}


def test_a_fallthrough_the_split_instruction_never_reaches_is_unsupported():
    # BRANCH +2 skips to BRANCH load; the observed fallthrough (the call rax)
    # is reached by no sub-block, only from load
    load = CODE_BASE + 5 * 4
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(op("BRANCH", [const(2, 4)]), copy(reg(RCX), const(1)), op("BRANCH", [ram(load)]))
               .label("pad").call_indirect(RAX)
               .add_rsp(0x28).ret()
               .ins(copy(reg(RAX), ram(SLOT)))
               .branch("pad"))
    assert _graph(builder).unsupported is not None
    assert _sites(builder) == {}


def test_a_loading_instruction_with_observed_flow_targets_is_not_taken():
    # the load's instruction lists the call rax as a flow target (an
    # override): the binding needs a plain instruction that only falls through
    builder = (_WithOverride(1, "pad").sub_rsp(0x28)
               .ins(copy(reg(RAX), ram(SLOT)))
               .label("pad").call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _sites(builder) == {}


def test_a_return_inside_an_instruction_is_unsupported():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(op("INT_NOTEQUAL", [reg(RCX), const(0)], flag), op("CBRANCH", [const(2, 4), flag]),
                    op("RETURN", [reg(RCX)]), copy(reg(RAX), ram(SLOT)))
               .call_indirect(RAX)
               .add_rsp(0x28).ret())
    assert _graph(builder).unsupported is not None
    assert _sites(builder) == {}
