"""A fresh/nonstack base is not an allocation-bound proof for its accesses.

The current allocator models expose no extent contract. These tests execute
only malloc (no free/realloc/UAF), then perform valid flat-RAM p-code accesses
outside the returned block. No C-language undefined-behavior premise is used.
"""

import pytest

from program_oracle import check_program
from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBP, RBX, RCX, RDI, REG, RSI, RSP, FunctionBuilder,
    add, const, copy, load, op, program_units, reg, slice_from, store, tmp,
)
from test_external_models import MODELS, THUNKS, _image
from tdo_v2.interprocedural import analyze_units
from tdo_v2.span_geometry import StorageObjectKind
from tdo_v2.summary_store import load_external_models


HEAP = 0x60000000                 # existing Interpreter malloc semantics
STACK = 0x70000000
FRAME_SLOT = STACK - 0x40 + 0x10
MASK = (1 << 64) - 1
WRAPPER = CODE_BASE + 0x800


@pytest.fixture(params=(("sparse", False), ("dense", False), ("sparse", True), ("dense", True)),
                ids=("sparse-default", "dense-default", "sparse-forward", "dense-forward"))
def mode(request, monkeypatch):
    engine, forward = request.param
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    if forward:
        monkeypatch.setenv("TDO_V2_FORWARD", "1")
    else:
        monkeypatch.delenv("TDO_V2_FORWARD", raising=False)


@pytest.fixture(scope="module")
def models():
    return load_external_models(MODELS, "x86:LE:64:default", "win64")


def _pools(seed):
    return {RSP: STACK, RBX: 0x1234567890ABCD00 + seed, RSI: 0xA1B2C3D4E5F60700 + seed}


def _case(case="stack", *, transit="direct", safe_access=False, wrapper=False, transform="add"):
    """One exact demand, one potentially aliasing malloc-derived write."""
    address, pointer, spill = tmp(0x100), tmp(0x108), tmp(0x110)
    builder = FunctionBuilder().sub_rsp(0x40)
    target, start, width = FRAME_SLOT, FRAME_SLOT, 8
    if case == "global":
        target = start = 0x71000080   # a constant-address RAM object above the allocator
    elif case == "negative":
        target = start = HEAP - 8
    elif case == "image-global":
        target = start = DATA_BASE + 0x80
    elif case == "partial-end":
        target, start = HEAP + 16, HEAP + 12
    elif case == "base-wide":
        target, start, width = HEAP + 16, HEAP, 32
    elif case == "wrap":
        target, start = 0, MASK - 3
    elif case == "other-fresh":
        target = start = HEAP + 0x1000
    if case != "other-fresh":
        if target == FRAME_SLOT:
            builder.ins(add(address, reg(RSP), const(0x10)), store(address, reg(RBX)))
        else:
            builder.ins(store(const(target), reg(RBX)))
    if wrapper:
        builder.call(WRAPPER)
    else:
        builder.ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
    base = reg(RAX)
    if case == "other-fresh":
        builder.ins(copy(reg(RBP), reg(RAX)), copy(reg(RCX), const(16))).call(THUNKS["malloc"])
        builder.ins(store(reg(RAX), reg(RBX)))
        base = reg(RBP)
    elif transit == "copy":
        builder.ins(copy(reg(RBP), reg(RAX)))
        base = reg(RBP)
    elif transit == "spill":
        builder.ins(add(spill, reg(RSP), const(0x20)), store(spill, reg(RAX)), load(reg(RBP), spill))
        base = reg(RBP)
    safe_writer = None
    if safe_access:
        safe_writer = f"1:{builder._address(len(builder._rows)):x}:0:STORE"
        builder.ins(store(base, reg(RBX)))
    writer = f"1:{builder._address(len(builder._rows)):x}:1:STORE"
    data = const(0xA1, width) if width == 32 else reg(RSI, width)
    displacement = const((start - HEAP) & MASK)
    address_op = add(pointer, base, reg(RDI)) if transform == "entry-add" else \
        op("INT_" + transform.upper(), [base, displacement], pointer)
    builder.ins(address_op, store(pointer, data))
    reader = f"1:{builder._address(len(builder._rows)):x}:0:LOAD"
    if case == "other-fresh":
        builder.ins(load(reg(R9), reg(RAX)))
    elif target == FRAME_SLOT:
        reader = f"1:{builder._address(len(builder._rows)):x}:1:LOAD"
        builder.ins(add(address, reg(RSP), const(0x10)), load(reg(R9), address))
    else:
        builder.ins(load(reg(R9), const(target)))
    safe_reader = None
    if safe_access:
        safe_reader = f"1:{builder._address(len(builder._rows)):x}:0:LOAD"
        builder.ins(load(reg(R8), base))
    builder.add_rsp(0x40).ret()
    bodies = [builder]
    if wrapper:
        bodies.append(FunctionBuilder(entry=WRAPPER).sub_rsp(0x28)
                      .ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"]).add_rsp(0x28).ret())
    return bodies, dict(reader=reader, writer=writer, target=target, start=start, width=width,
                        safe_reader=safe_reader, safe_writer=safe_writer)


def _analyze(bodies, models, *, strict=True):
    units = program_units(*bodies)
    options = dict(assume_entry_values_not_frame=False,
                   assume_opaque_callees_leave_no_stack_addresses=False,
                   assume_globals_disjoint_from_stack=False) if strict else {}
    results = analyze_units(units, image_info=_image(), external_models=models, **options)
    return results["1:1000"], {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}


@pytest.mark.parametrize("case", ("stack", "stack-default", "global", "image-global", "other-fresh",
                                 "negative", "partial-end", "base-wide", "wrap"))
def test_unknown_extent_cannot_exclude_an_outside_access_from_existing_ram(mode, models, case):
    bodies, points = _case("stack" if case == "stack-default" else case)
    item, program = _analyze(bodies, models, strict=case != "stack-default")
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(4),
                           register_pools=_pools, havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()},
                           address_bits={1: 64})
    assert report.runs == 4 and report.checked and not report.unsupported
    assert not report.silent, report.silent[:3]
    node = item.normalized.dependencies.node_for_key("op:" + points["reader"])
    assert not slice_from(item.normalized, node).is_complete


@pytest.mark.parametrize("transit", ("copy", "spill"))
def test_pointer_copy_or_exact_spill_is_not_an_access_bounds_certificate(mode, models, transit):
    bodies, points = _case(transit=transit)
    item, program = _analyze(bodies, models)
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(4),
                           register_pools=_pools, havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs == 4 and not report.unsupported and not report.silent, report.silent[:3]
    assert not slice_from(item.normalized, item.normalized.dependencies.node_for_key(
        "op:" + points["reader"])).is_complete


@pytest.mark.parametrize("transform", ("or", "xor", "entry-add"))
def test_opaque_or_entry_arithmetic_cannot_launder_a_fresh_base(mode, models, transform):
    # For this actual allocator base the offset has no overlapping set bits:
    # OR, XOR and ADD all reach FRAME_SLOT, without assuming general equality.
    bodies, points = _case(transform=transform)
    item, program = _analyze(bodies, models, strict=False)
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(4),
                           register_pools=lambda seed: {**_pools(seed), RDI: FRAME_SLOT - HEAP},
                           havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs == 4 and report.checked and not report.unsupported
    assert not report.silent, report.silent[:3]
    assert not slice_from(item.normalized, item.normalized.dependencies.node_for_key(
        "op:" + points["reader"])).is_complete


@pytest.mark.parametrize("alternative", ("null", "other-fresh"))
def test_join_with_an_outside_address_is_not_a_nonstack_certificate(mode, models, alternative):
    address, pointer = tmp(0x100), tmp(0x108)
    builder = (FunctionBuilder().sub_rsp(0x40)
               .ins(add(address, reg(RSP), const(0x10)), store(address, reg(RBX)))
               .ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"]))
    base = reg(RAX)
    if alternative == "other-fresh":
        builder.ins(copy(reg(RBP), reg(RAX)), copy(reg(RCX), const(16))).call(THUNKS["malloc"])
        base = reg(RBP)
    builder.cbranch("alternative", reg(RDI, 1))
    builder.ins(add(pointer, base, const(FRAME_SLOT - HEAP))).branch("join")
    builder.label("alternative").ins(copy(pointer, const(0) if alternative == "null" else reg(RAX)))
    builder.label("join").ins(store(pointer, reg(RSI)))
    reader = f"1:{builder._address(len(builder._rows)):x}:1:LOAD"
    builder.ins(add(address, reg(RSP), const(0x10)), load(reg(R9), address)).add_rsp(0x40).ret()
    item, program = _analyze([builder], models, strict=False)
    # Both join arms execute: even seeds overwrite the frame; odd seeds write
    # valid flat RAM at zero / at the second allocation. No free is involved.
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(4),
                           register_pools=lambda seed: {**_pools(seed), RDI: seed & 1},
                           havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs == 4 and report.checked and not report.unsupported
    assert not report.silent, report.silent[:3]
    assert not slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + reader)).is_complete


def test_nonstack_summary_result_does_not_make_its_offset_addresses_nonstack(mode, models):
    bodies, points = _case(wrapper=True)
    item, program = _analyze(bodies, models)
    (effect,) = [effect for _, effect in item.normalized.proven_call_effects]
    assert any(run.value == ("nonstack",) for run in effect.runs)
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(4),
                           register_pools=_pools, havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs == 4 and not report.unsupported and not report.silent, report.silent[:3]
    assert not slice_from(item.normalized, item.normalized.dependencies.node_for_key(
        "op:" + points["reader"])).is_complete


def test_one_safe_base_access_does_not_license_other_offsets_of_the_same_object(mode, models):
    bodies, points = _case(safe_access=True)
    item, program = _analyze(bodies, models)
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(4),
                           register_pools=_pools, havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs == 4 and not report.unsupported and not report.silent, report.silent[:3]
    assert not slice_from(item.normalized, item.normalized.dependencies.node_for_key(
        "op:" + points["reader"])).is_complete
    ssa = item.normalized.memory_ssa
    (read,) = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == points["safe_reader"]
               and row.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)]
    assert len(read.fragments) == 1
    (identifier,) = read.fragments[0].definition_ids
    assert ssa.definitions[identifier].operation_key == points["safe_writer"]


def test_same_address_store_load_keeps_exact_ssa_bytes_without_nonalias_claim(mode, models):
    builder = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
               .ins(store(reg(RAX), reg(RSI))).ins(load(reg(R9), reg(RAX))).add_rsp(0x28).ret())
    item, program = _analyze([builder], models)
    ssa = item.normalized.memory_ssa
    (read,) = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == "1:1010:0:LOAD"
               and row.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)]
    assert read.span.size == 8 and len(read.fragments) == 1
    (identifier,) = read.fragments[0].definition_ids
    definition = ssa.definitions[identifier]
    assert definition.operation_key == "1:100c:0:STORE" and definition.span == read.span
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(4),
                           register_pools=_pools, havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs == 4 and report.checked and not report.unsupported and not report.silent
