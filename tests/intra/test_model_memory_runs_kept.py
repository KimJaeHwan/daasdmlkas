"""A call that clobbers memory keeps the bytes its external model's memory
runs write at an exactly known place (``normalize._kept_call_memory``): the
model's listed writes are the values when it returns, ``other_memory`` is
about the rest. strcpy: dst[0] = src[0] always (docs 25.15, DFB122)."""

import json
from pathlib import Path

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, load,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models

MODELS = sorted((Path(__file__).resolve().parents[2] / "models" / "external").glob("*.json"))
STRCPY = CODE_BASE + 0xE00
OPAQUE = CODE_BASE + 0xD00  # no function, no model: an opaque call
CALLER = CODE_BASE + 0x400
HAVOC = (REG, RSP, 8)
T = tmp(0x100)


def _analyze(*functions):
    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "strcpy", None, (), ((1, STRCPY),)),), (), ())
    return analyze_units(program_units(*functions), image_info=image,
                         external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))


def _check(results, key):
    analyzed = results[key]
    return check_program(analyzed.normalized, analyzed.unit.observation, {}, seeds=range(6),
                         register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                         havoc_calls=HAVOC, externals={(1, STRCPY): "strcpy"})


def _src(builder, value=None):
    """src = [rsp+0x20] = (bl or ``value``'s low byte, 0)."""
    return (builder.ins(add(T, reg(RSP), const(0x20)), store(T, value or reg(RBX, 1)))
            .ins(add(T, reg(RSP), const(0x21)), store(T, const(0, 1))))


def _strcpy(builder, *destination):
    """strcpy(dst = rsp+0x30, or what the ``destination`` ops set, src = rsp+0x20)."""
    builder.ins(*(destination or (add(reg(RCX), reg(RSP), const(0x30)),)))
    return builder.ins(add(reg(RDX), reg(RSP), const(0x20))).call(STRCPY)


def _reads(builder):
    """r9b = dst[0], r8b = dst[1]."""
    return (builder.ins(add(T, reg(RSP), const(0x30)), load(reg(R9, 1), T))
            .ins(add(T, reg(RSP), const(0x31)), load(reg(R8, 1), T)))


def _slice(results, key, index):
    function = results[key].normalized
    entry = function.scopes.function.entry.byte_offset
    return slice_from(function, operation_node_at(function, index, 1, entry=entry))


def test_strcpy_keeps_dst0_equal_to_src0():
    builder = _reads(_strcpy(_src(FunctionBuilder().sub_rsp(0x48)))).add_rsp(0x48).ret()
    results = _analyze(builder)
    item = results["1:1000"]
    ((call, label),) = item.declared.items()
    assert label == "external-model:crt-win64/strcpy@v5"
    assert not item.proven[call].preserves_memory and item.proven[call].memory_runs_final
    assert dict(item.normalized.kept_call_memory)[call]
    first, second = _slice(results, "1:1000", 6), _slice(results, "1:1000", 7)
    assert first.is_complete and RBX in first.register_bytes
    assert not second.is_complete  # dst[1]: written only when src[0] != 0
    assert _check(results, "1:1000").silent == []


def test_a_source_byte_with_debt_keeps_its_debt():
    # src[0] = al after an opaque call: the copy carries that debt
    builder = FunctionBuilder().sub_rsp(0x48).call(OPAQUE)
    builder = _reads(_strcpy(_src(builder, reg(RAX, 1)))).add_rsp(0x48).ret()
    results = _analyze(builder)
    assert not _slice(results, "1:1000", 7).is_complete
    assert _check(results, "1:1000").silent == []


def test_a_later_opaque_call_clobbers_the_kept_byte_again():
    builder = _strcpy(_src(FunctionBuilder().sub_rsp(0x48))).call(OPAQUE)
    builder = _reads(builder).add_rsp(0x48).ret()
    results = _analyze(builder)
    assert not _slice(results, "1:1000", 7).is_complete
    assert _check(results, "1:1000").silent == []


def test_an_uncertain_destination_keeps_nothing():
    # dst pointer stored, an opaque call, then reloaded: its address carries
    # call-clobber debt, so the model's write is an uncertain-address writer
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(reg(RCX), reg(RSP), const(0x30)))
               .ins(add(T, reg(RSP), const(0x38)), store(T, reg(RCX)))
               .call(OPAQUE))
    builder = _src(builder)
    builder = _strcpy(builder, add(T, reg(RSP), const(0x38)), load(reg(RCX), T))
    builder = _reads(builder).add_rsp(0x48).ret()
    results = _analyze(builder)
    item = results["1:1000"]
    assert not item.normalized.kept_call_memory
    assert not _slice(results, "1:1000", 9).is_complete
    assert _check(results, "1:1000").silent == []


def test_a_wrapper_summary_exports_the_kept_byte():
    # wrapper(dst, src) = strcpy(dst, src): its summary states dst[0] (a
    # memory run from src[0]), not an unknown byte; its caller still
    # clobbers memory at the wrapper call -- the keeping is for external
    # models only (scope B, docs 25.15), so the read gets the value with debt
    wrapper = FunctionBuilder().sub_rsp(0x28).call(STRCPY).add_rsp(0x28).ret()
    caller = _src(FunctionBuilder(entry=CALLER).sub_rsp(0x48))
    caller = (caller.ins(add(reg(RCX), reg(RSP), const(0x30)))
              .ins(add(reg(RDX), reg(RSP), const(0x20))).call(CODE_BASE))
    caller = _reads(caller).add_rsp(0x48).ret()
    results = _analyze(wrapper, caller)
    key = f"1:{CALLER:x}"
    (effect,) = results[key].proven.values()
    assert not effect.preserves_memory and not effect.memory_runs_final
    runs = [run for run in effect.memory_runs if run.write.size == 1 and run.write.displacement == 0]
    assert len(runs) == 1 and runs[0].write.anchor.start == RCX and runs[0].loads
    first = _slice(results, key, 6)
    assert RBX in first.register_bytes and not first.is_complete
    assert _check(results, key).silent == []


def test_dense_and_sparse_engines_agree(monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_CROSSCHECK", "dense")
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_CROSSCHECK", "dense")
    builder = _reads(_strcpy(_src(FunctionBuilder().sub_rsp(0x48)))).add_rsp(0x48).ret()
    assert _slice(_analyze(builder), "1:1000", 6).is_complete


# -- wider writes, below the stack (reviews) -------------------------------------

def _wide_model(directory):
    """"wide(dst, src)": dst[0, 8) = src[0, 8), everything else unknown."""
    raw = {"format_version": 1, "kind": "declared", "id": "wide-test", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64",
           "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
           "entries": [{"name": "wide", "registers": [],
                        "memory": [{"write": {"base": [8, 8], "disp": 0, "size": 8}, "from": [[8, 8], [16, 8]],
                                    "loads": [{"base": [16, 8], "disp": 0, "size": 8}]}],
                        "other_memory": "clobbered"}]}
    path = Path(directory) / "wide.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return load_external_models([path], "x86:LE:64:default", "win64")


def test_an_eight_byte_write_split_into_atoms_is_kept_whole(tmp_path):
    # dst+0 and dst+4 written separately first: memory SSA splits dst[0, 8)
    wide = CODE_BASE + 0xE80
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(T, reg(RSP), const(0x20)), store(T, reg(RBX)))
               .ins(add(T, reg(RSP), const(0x30)), store(T, reg(RSI, 4)))
               .ins(add(T, reg(RSP), const(0x34)), store(T, reg(RDI, 4)))
               .ins(add(reg(RCX), reg(RSP), const(0x30)))
               .ins(add(reg(RDX), reg(RSP), const(0x20)))
               .call(wide)
               .ins(add(T, reg(RSP), const(0x30)), load(reg(R9), T))
               .ins(add(T, reg(RSP), const(0x38)), load(reg(R8, 1), T))
               .add_rsp(0x48).ret())
    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "wide", None, (), ((1, wide),)),), (), ())
    results = analyze_units(program_units(builder), image_info=image, external_models=_wide_model(tmp_path))
    ((call, spans),) = results["1:1000"].normalized.kept_call_memory
    assert [span.size for span in spans] == [8]
    whole = _slice(results, "1:1000", 7)
    assert whole.is_complete and set(range(RBX, RBX + 8)) <= whole.register_bytes
    assert not set(range(RSI, RSI + 4)) & whole.register_bytes
    assert not _slice(results, "1:1000", 8).is_complete  # dst+8: the rest of memory


def test_a_destination_below_the_stack_pointer_has_no_silent_miss():
    # dst below the call-time stack pointer (the callee's frame): outside the
    # model's preconditions (dst must be the caller's writable storage), and
    # the oracle's strcpy writes no frame of its own -- this only checks the
    # graph against that run; the keeping itself rests on the model contract
    builder = _src(FunctionBuilder().sub_rsp(0x48))
    builder = _strcpy(builder, add(reg(RCX), reg(RSP), const(-0x40 & 0xFFFF_FFFF_FFFF_FFFF)))
    builder = (builder.ins(add(T, reg(RSP), const(-0x40 & 0xFFFF_FFFF_FFFF_FFFF)), load(reg(R9, 1), T))
               .add_rsp(0x48).ret())
    results = _analyze(builder)
    assert _check(results, "1:1000").silent == []
