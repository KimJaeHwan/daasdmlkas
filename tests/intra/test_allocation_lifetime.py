"""Original-SSA allocation facts for opt-in, symbol-specific lifecycle contracts.

These tests exercise the scoped lifetime analysis; they do not claim that a
live allocation alone discharges a CALL's separate byte-preservation debt.
"""

from dataclasses import replace

import pytest

from synthetic import (RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder,
                       add, const, copy, load, op, program_units, reg, store, tmp)
from test_external_models import MODELS, THUNKS, _image
from test_lifecycle_contracts import _contract as _typed_contract
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2._forward_memory import RefinementRefused
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models


FLAG = tmp(0x300, 1)
SLOT = tmp(0x100)


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


@pytest.fixture(scope="module")
def models():
    return load_external_models(MODELS, "x86:LE:64:default", "win64")


def _key(builder, ordinal, opcode):
    return f"1:{builder._address(len(builder._rows)):x}:{ordinal}:{opcode}"


def _contracts(models, *, allocate=True, release=False, resize=False, allocation_changes=None,
               resize_changes=None):
    file, _ = models.lookup("malloc")
    contracts = []
    if allocate:
        contracts.append(replace(_typed_contract(file, "allocate", **(allocation_changes or {})),
                                 contract_id="audited-malloc", owned_footprint=True))
    if release:
        contracts.append(replace(_typed_contract(file, "release"), contract_id="audited-free"))
    if resize:
        outcomes = dict(failure="retain", zero_size="release", inplace="retain", moved="replace")
        outcomes.update(resize_changes or {})
        contracts.append(replace(_typed_contract(file, "resize", **outcomes),
                                 contract_id="audited-realloc", owned_footprint=True))
    return tuple(contracts)


def _run(builder, models, contracts, *, extra=(), image=None):
    result = analyze_units(
        program_units(builder, *extra), image_info=_image() if image is None else image,
        external_models=models,
        lifecycle_contracts=contracts, private_frame_above=40,
        assume_globals_disjoint_from_stack=True,
        assume_entry_values_not_frame=False,
        assume_opaque_callees_leave_no_stack_addresses=False,
    )
    item = result["1:1000"]
    return item, AllocationAnalysis(item, results=result)


def _begin():
    builder = (FunctionBuilder().sub_rsp(0x60)
               .ins(copy(reg(RCX), const(8))))
    call = _key(builder, 2, "CALL")
    builder.call(THUNKS["malloc"]).ins(copy(reg(RBX), reg(RAX)))
    return builder, call


def _guard(builder):
    builder.cbranch("done", FLAG, op("INT_EQUAL", [reg(RBX), const(0)], FLAG))
    return builder


def _finish(builder):
    return builder.label("done").add_rsp(0x60).ret()


def _writer(builder, pointer=RDI, *, displacement=4, width=4):
    if displacement is not None:
        builder.ins(add(reg(pointer), reg(pointer), const(displacement & ((1 << 64) - 1))))
    key = _key(builder, 0, "STORE")
    builder.ins(store(reg(pointer), const(0x12345678, width)))
    return key


def test_guarded_full_pointer_copy_spill_reload_and_offset_is_live(models):
    builder, allocation = _begin()
    _guard(builder)
    builder.ins(add(SLOT, reg(RSP), const(0x30)), store(SLOT, reg(RBX)))
    builder.ins(load(reg(RDI), SLOT))
    writer = _writer(builder)
    item, analysis = _run(_finish(builder), models, _contracts(models))
    assert allocation in analysis.contracts
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert len(pointer.targets) == 1
    assert next(iter(pointer.targets)).offset == 4
    evidence = analysis.lifetime(pointer, writer)
    assert evidence.live and evidence.reason == "live"
    assert analysis.access(writer) is not None
    assert any(label.startswith("lifecycle-contract:audited-malloc@v1#")
               for label in analysis.access(writer).requires)
    assert item.normalized.memory_ssa is analysis.ssa


def test_guarded_full_pointer_copy_without_spill_is_live(models):
    builder, allocation = _begin()
    _guard(builder)
    builder.ins(copy(reg(RDI), reg(RBX)))
    writer = _writer(builder, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert allocation in analysis.contracts
    assert not pointer.unknown and len(pointer.targets) == 1
    assert analysis.lifetime(pointer, writer).live
    assert analysis.access(writer).live


def test_nullable_allocation_without_nonnull_guard_is_not_live(models):
    builder, _ = _begin()
    builder.ins(copy(reg(RDI), reg(RBX)))
    writer = _writer(builder, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert pointer.targets and pointer.nulls
    assert not analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


def test_liveness_without_owned_extent_does_not_prove_store_range(models):
    builder, _ = _begin()
    _guard(builder)
    writer = _writer(builder, pointer=RBX, displacement=None)
    contract = replace(_contracts(models)[0], owned_footprint=False)
    _, analysis = _run(_finish(builder), models, (contract,))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


def test_half_overwritten_spill_cannot_reassemble_one_pointer(models):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(add(SLOT, reg(RSP), const(0x30)), store(SLOT, reg(RBX)))
    builder.ins(add(tmp(0x108), SLOT, const(4)), store(tmp(0x108), const(0, 4)))
    builder.ins(load(reg(RDI), SLOT))
    writer = _writer(builder, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert pointer.unknown
    assert analysis.access(writer) is None


@pytest.mark.parametrize("extension", ("INT_ZEXT", "INT_SEXT"))
def test_truncated_then_extended_pointer_does_not_recover_allocation_identity(models, extension):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(op("SUBPIECE", [reg(RBX), const(0, 4)], reg(RDI, 4)))
    builder.ins(op(extension, [reg(RDI, 4)], reg(RDI)))
    writer = _writer(builder, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert not pointer.targets
    assert analysis.access(writer) is None


def test_partial_pointer_overwrite_before_null_guard_cannot_certify_liveness(models):
    builder, _ = _begin()
    builder.ins(copy(reg(RDI), reg(RBX)))
    builder.ins(copy(reg(RDI + 4, 4), const(0, 4)))
    builder.cbranch("done", FLAG, op("INT_EQUAL", [reg(RDI), const(0)], FLAG))
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert pointer.targets
    assert not analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


def test_debt_on_null_predicate_cannot_certify_liveness(models):
    builder, _ = _begin()
    builder.ins(copy(reg(RCX), reg(RBX)))
    builder.call(THUNKS["strlen"])  # modeled quiet call, but RCX is volatile
    compare = _key(builder, 0, "INT_EQUAL")
    builder.cbranch("done", FLAG, op("INT_EQUAL", [reg(RCX), const(0)], FLAG))
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    assert analysis.read_definition(compare, analysis.port((RCX, 8))) is None
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert pointer.targets  # RBX itself survived; only the guard is unproved
    assert not analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


def test_store_address_is_not_mistaken_for_stored_zero_value(models):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(store(reg(RBX), const(0)))
    builder.ins(load(reg(RDI), reg(RBX)))
    writer = _writer(builder, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert not pointer.targets and pointer.nulls == frozenset({None})
    assert analysis.access(writer) is None


def test_free_of_copy_alias_ends_original_allocation(models):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(copy(reg(RDI), reg(RBX)), copy(reg(RCX), reg(RDI)))
    release = _key(builder, 2, "CALL")
    builder.call(THUNKS["free"])
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models, release=True))
    argument = analysis.argument(release, (RCX, 8))
    assert release in analysis.contracts and len(argument.targets) == 1 and not argument.unknown
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    lifetime = analysis.lifetime(pointer, writer)
    assert not lifetime.live and "ended" in lifetime.states[0][1]
    assert analysis.access(writer) is None


def test_free_on_only_one_cfg_arm_prevents_must_live(models):
    builder, _ = _begin()
    _guard(builder)
    builder.cbranch("after_free", reg(RSI, 1))
    builder.ins(copy(reg(RCX), reg(RBX)))
    release = _key(builder, 2, "CALL")
    builder.call(THUNKS["free"])
    builder.label("after_free")
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models, release=True))
    assert release in analysis.contracts
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    lifetime = analysis.lifetime(pointer, writer)
    assert not lifetime.live
    assert set(lifetime.states[0][1]) >= {"live", "ended"}
    assert analysis.access(writer) is None


def test_unknown_free_argument_may_alias_and_invalidate(models):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(copy(reg(RCX), reg(RSI)))
    release = _key(builder, 2, "CALL")
    builder.call(THUNKS["free"])
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models, release=True))
    assert release in analysis.contracts
    assert analysis.argument(release, (RCX, 8)).unknown
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert not analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


def test_exact_xor_edi32_then_zext_rdi64_free_null_keeps_other_allocation_live(models):
    builder, allocation = _begin()
    _guard(builder)
    builder.ins(op("INT_XOR", [reg(RDI, 4), reg(RDI, 4)], reg(RDI, 4)))
    builder.ins(op("INT_ZEXT", [reg(RDI, 4)], reg(RDI)))
    builder.ins(copy(reg(RCX), reg(RDI)))  # Win64 free port; the EDI idiom is unchanged.
    release = _key(builder, 2, "CALL")
    builder.call(THUNKS["free"])
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models, release=True))
    assert allocation in analysis.contracts and release in analysis.contracts
    argument = analysis.argument(release, (RCX, 8))
    assert not argument.unknown and not argument.targets and argument.nulls == frozenset({None})
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is not None


@pytest.mark.parametrize("source", ("low32-only", "zero-plus-eight", "nonzero", "top", "debt-load-zero"))
def test_only_exact_fullwidth_zero_can_prove_free_null(models, source):
    builder, _ = _begin()
    _guard(builder)
    if source == "low32-only":
        builder.ins(op("INT_XOR", [reg(RDI, 4), reg(RDI, 4)], reg(RDI, 4)))
        builder.ins(copy(reg(RCX), reg(RDI)))  # high four RDI bytes remain unproved
    elif source == "zero-plus-eight":
        builder.ins(copy(reg(RCX), const(0)), add(reg(RCX), reg(RCX), const(8)))
    elif source == "nonzero":
        builder.ins(copy(reg(RCX), const(8)))
    elif source == "top":
        builder.ins(copy(reg(RCX), reg(RSI)))
    else:
        builder.ins(add(SLOT, reg(RSP), const(0x30)), store(SLOT, const(0)))
        builder.ins(store(reg(RSI), const(1)))  # may overlap the zero slot
        builder.ins(load(reg(RCX), SLOT))
    release = _key(builder, 2, "CALL")
    builder.call(THUNKS["free"])
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models, release=True))
    argument = analysis.argument(release, (RCX, 8))
    assert release in analysis.contracts
    assert not argument.targets
    assert not (not argument.unknown and argument.nulls == frozenset({None}))
    if source in ("low32-only", "zero-plus-eight", "top", "debt-load-zero"):
        assert argument.unknown
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert not analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


@pytest.mark.parametrize("kind", ("release", "resize"))
def test_unproved_interior_other_allocation_invalidates_first_allocation(models, kind):
    builder, first = _begin()
    _guard(builder)
    builder.ins(copy(reg(RCX), const(8)))
    second = _key(builder, 2, "CALL")
    builder.call(THUNKS["malloc"]).ins(copy(reg(RSI), reg(RAX)))
    builder.cbranch("done", FLAG, op("INT_EQUAL", [reg(RSI), const(0)], FLAG))
    builder.ins(copy(reg(RCX), reg(RSI)), add(reg(RCX), reg(RCX), const(1)))
    if kind == "resize":
        builder.ins(copy(reg(RDX), const(16)))
    release = _key(builder, 2, "CALL")
    builder.call(THUNKS["free" if kind == "release" else "realloc"])
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models,
                       _contracts(models, release=kind == "release", resize=kind == "resize"))
    assert first in analysis.contracts and second in analysis.contracts and release in analysis.contracts
    old = analysis.argument(release, (RCX, 8))
    assert len(old.targets) == 1 and next(iter(old.targets)).allocation.event == second
    assert next(iter(old.targets)).offset == 1
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert pointer.targets and not analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


def test_resize_does_not_make_an_old_alias_unconditionally_live(models):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), const(8)))
    resize = _key(builder, 2, "CALL")
    builder.call(THUNKS["realloc"])
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models, resize=True))
    assert resize in analysis.contracts
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    lifetime = analysis.lifetime(pointer, writer)
    assert not lifetime.live
    assert "ended" in lifetime.states[0][1]
    assert analysis.access(writer) is None


@pytest.mark.parametrize("old_source", ("unknown", "ended", "interior"))
def test_realloc_result_guard_cannot_redeem_invalid_old_object(models, old_source):
    builder, _ = _begin()
    _guard(builder)
    if old_source == "unknown":
        builder.ins(copy(reg(RCX), reg(RSI)))
    elif old_source == "ended":
        builder.ins(copy(reg(RCX), reg(RBX)))
        builder.call(THUNKS["free"])
        builder.ins(copy(reg(RCX), reg(RBX)))
    else:
        builder.ins(copy(reg(RCX), reg(RBX)))
        builder.ins(add(reg(RCX), reg(RCX), const(4)))
    builder.ins(copy(reg(RDX), const(8)))
    resize = _key(builder, 2, "CALL")
    builder.call(THUNKS["realloc"])
    builder.cbranch("done", FLAG, op("INT_EQUAL", [reg(RAX), const(0)], FLAG))
    writer = _writer(builder, pointer=RAX, displacement=None)
    contracts = _contracts(models, release=old_source == "ended", resize=True,
                           resize_changes={"inplace": "replace"})
    _, analysis = _run(_finish(builder), models, contracts)
    assert resize in analysis.contracts
    assert analysis.argument(resize, (RCX, 8)).unknown == (old_source == "unknown")
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert not analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


@pytest.mark.parametrize("arithmetic", ("INT_ADD", "INT_SUB"))
def test_realloc_literal_null_plus_or_minus_eight_is_not_a_valid_old_object(models, arithmetic):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(copy(reg(RCX), const(0)), op(arithmetic, [reg(RCX), const(8)], reg(RCX)),
                copy(reg(RDX), const(16)))
    resize = _key(builder, 2, "CALL")
    builder.call(THUNKS["realloc"])
    builder.cbranch("done", FLAG, op("INT_EQUAL", [reg(RAX), const(0)], FLAG))
    writer = _writer(builder, pointer=RAX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models, resize=True,
                              resize_changes={"inplace": "replace"}))
    assert resize in analysis.contracts
    old = analysis.argument(resize, (RCX, 8))
    assert not old.targets
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert not analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


def test_unmodelled_intervening_call_invalidates_lifetime(models):
    builder, _ = _begin()
    _guard(builder)
    unknown_call = _key(builder, 2, "CALL")
    builder.call(0x1700)
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    assert unknown_call not in analysis.contracts
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert pointer.unknown  # the unmodelled call may clobber physical RBX
    precursor = analysis.argument(unknown_call, (RBX, 8))
    assert precursor.targets
    lifetime = analysis.lifetime(precursor, writer)
    assert not lifetime.live and "unknown" in lifetime.states[0][1]
    assert analysis.access(writer) is None


@pytest.mark.parametrize("mode", ("absent", "wrong-digest", "wrong-symbol", "wrong-port", "ambiguous"))
def test_unmatched_or_ambiguous_contract_never_creates_birth(models, mode):
    builder, allocation = _begin()
    _guard(builder)
    writer = _writer(builder, pointer=RBX, displacement=None)
    contract = _contracts(models)[0]
    if mode == "absent":
        contracts = ()
    elif mode == "wrong-digest":
        contracts = (replace(contract, model_digest="0" * 64),)
    elif mode == "wrong-symbol":
        contracts = (replace(contract, symbol_names=("calloc",)),)
    elif mode == "wrong-port":
        contracts = (replace(contract, result=(1, 8)),)
    else:
        contracts = (contract, replace(contract, contract_id="second-audit"))
    _, analysis = _run(_finish(builder), models, contracts)
    assert allocation not in analysis.contracts
    assert analysis.access(writer) is None


def test_actual_import_symbol_change_invalidates_a_matching_model_contract(models):
    builder, allocation = _begin()
    _guard(builder)
    writer = _writer(builder, pointer=RBX, displacement=None)
    image = _image()
    image = replace(image, imports=tuple(replace(symbol, name="calloc")
                                         if symbol.name == "malloc" else symbol
                                         for symbol in image.imports))
    assert any(symbol.name == "calloc" and (1, THUNKS["malloc"]) in symbol.thunks
               for symbol in image.imports)
    _, analysis = _run(_finish(builder), models, _contracts(models), image=image)
    assert allocation in analysis.models  # still the shared malloc/calloc ModelEntry
    assert allocation not in analysis.contracts  # but no malloc-specific lifecycle claim
    assert analysis.access(writer) is None


@pytest.mark.parametrize("displacement,width", ((6, 4), (-4, 4), (0, 16)))
def test_live_pointer_outside_owned_extent_is_not_an_access_proof(models, displacement, width):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(copy(reg(RDI), reg(RBX)))
    writer = _writer(builder, displacement=displacement, width=width)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is None


def test_repeated_allocation_callsite_keeps_family_identity_but_certifies_current_result(models):
    builder = FunctionBuilder().sub_rsp(0x60).label("again")
    builder.ins(copy(reg(RCX), const(8)))
    allocation = _key(builder, 2, "CALL")
    builder.call(THUNKS["malloc"]).ins(copy(reg(RBX), reg(RAX)))
    builder.cbranch("again", reg(RSI, 1))
    _guard(builder)
    writer = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models))
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert pointer.targets
    assert any(target.allocation.event == allocation and target.allocation.occurrence == "family"
               for target in pointer.targets)
    ref = next(iter(pointer.targets)).allocation
    assert analysis.local_occurrence(pointer, ref, writer)
    assert analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is not None


def test_liveness_is_bound_to_the_reader_point_across_a_free(models):
    builder, _ = _begin()
    _guard(builder)
    before = _writer(builder, pointer=RBX, displacement=None)
    builder.ins(copy(reg(RCX), reg(RBX)))
    builder.call(THUNKS["free"])
    after = _writer(builder, pointer=RBX, displacement=None)
    _, analysis = _run(_finish(builder), models, _contracts(models, release=True))
    assert before != after and analysis.access(before).live
    assert analysis.access(after) is None


def test_forward_off_refuses_lifecycle_access_proof(models, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    builder, _ = _begin()
    _guard(builder)
    _writer(builder, pointer=RBX, displacement=None)
    with pytest.raises(RefinementRefused, match="lifecycle input policy"):
        _run(_finish(builder), models, _contracts(models))


def test_different_readonly_image_reader_is_refused(models):
    builder, _ = _begin()
    _guard(builder)
    _writer(builder, pointer=RBX, displacement=None)
    item, _ = _run(_finish(builder), models, _contracts(models))
    with pytest.raises(RefinementRefused, match="lifecycle input policy"):
        AllocationAnalysis(item, readonly_image=object())
