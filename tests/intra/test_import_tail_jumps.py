"""A terminal ``jmp`` to an import thunk outside the Bundle (``jmp free``) is a
tail call taking the import's model, as ``jmp [__imp_free]`` already was
(``interprocedural.import_call_sites``). 09 had 1 (debug) / 4 (release) such
jumps left as unknown tail exits."""

from pathlib import Path

from synthetic import CODE_BASE, RCX, FunctionBuilder, copy, program_units, reg
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models

MODELS = sorted((Path(__file__).resolve().parents[2] / "models" / "external").glob("*.json"))
FREE = CODE_BASE + 0xE00     # the free import thunk (not a Bundle function)
ABORT = CODE_BASE + 0xE10


def _analyze(builder):
    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "free", None, (), ((1, FREE),)),
                                        ImportedSymbol("CRT", "abort", None, (), ((1, ABORT),))), (), ())
    # (another function with a call: its call shape names the program's stack
    # pointer, which a tail call composes through)
    other = FunctionBuilder(entry=CODE_BASE + 0x400).sub_rsp(0x28).call(CODE_BASE + 0x800).add_rsp(0x28).ret()
    return analyze_units(program_units(builder, other), image_info=image,
                         external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))["1:1000"]


def test_a_jump_to_an_import_thunk_takes_the_model():
    analyzed = _analyze(FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RCX))).add_rsp(0x28).tail_call(FREE))
    (jump,) = [key for key in analyzed.proven if key.endswith(":BRANCH")]
    assert analyzed.declared[jump].startswith("external-model:crt-win64/free@")
    assert analyzed.summary is not None and analyzed.summary.tail_exits == ()


def test_without_models_the_jump_stays_a_tail_exit():
    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "free", None, (), ((1, FREE),)),), (), ())
    analyzed = analyze_units(program_units(FunctionBuilder().tail_call(FREE)), image_info=image)["1:1000"]
    assert not analyzed.proven and analyzed.summary.tail_exits


def test_a_jump_to_an_in_bundle_function_at_a_thunk_address_composes_its_body():
    # the program has a function at the thunk's address: the jump composes
    # that body -- or, when that body has an unknown tail exit of its own,
    # stays unknown -- never the import's model
    for thunk_body, composed in ((FunctionBuilder(entry=FREE).ret(), True),
                                 (FunctionBuilder(entry=FREE).tail_call(CODE_BASE + 0x900), False)):
        image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "free", None, (), ((1, FREE),)),), (), ())
        other = FunctionBuilder(entry=CODE_BASE + 0x400).sub_rsp(0x28).call(CODE_BASE + 0x800).add_rsp(0x28).ret()
        caller = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RCX))).add_rsp(0x28).tail_call(FREE)
        analyzed = analyze_units(program_units(caller, other, thunk_body), image_info=image,
                                 external_models=load_external_models(MODELS, "x86:LE:64:default",
                                                                      "win64"))["1:1000"]
        jumps = [key for key in analyzed.proven if key.endswith(":BRANCH")]
        assert not any(label.startswith("external-model:crt-win64/free") for label in analyzed.declared.values())
        assert bool(jumps) == composed


def test_a_jump_to_a_function_that_never_returns_stays_with_noreturn_jumps():
    analyzed = _analyze(FunctionBuilder().sub_rsp(0x28).add_rsp(0x28).tail_call(ABORT))
    assert not [key for key in analyzed.proven if key.endswith(":BRANCH")]
    assert analyzed.declared and next(iter(analyzed.declared.values())).startswith("external-model:crt-win64/abort@")
