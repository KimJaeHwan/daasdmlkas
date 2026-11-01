"""Forward consumers use sealed byte ports, never guessed memory contents.

The actual DFB201 table has finite LOAD addresses. Its downstream numeric
target range is a conservative 69-value envelope around five original table
alternatives; neither fact is whole-function completion.
"""

from pathlib import Path
import os

import pytest

from pcode_interpreter import Interpreter
from synthetic import (CONST, DATA_BASE, RAM, REG, RAX, RCX, RDI, RDX, RSI, RSP,
                       FunctionBuilder, add, const, copy, load, op, program_units, reg, store, tmp)
from test_guarded_image_consumers import _actual_unit, _record
from test_guarded_image_reads import _image, _normalize
from tdo_v2._memory_read_sources import read_source
from tdo_v2.forward import _analyze
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.operation_records import _compute, render


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def _engine(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _facts(normalized, unit, image=None):
    return {fact.operation: fact for fact in _analyze(normalized, unit, readonly_image=image).facts}


def _numbers(claim):
    interval = claim.numeric()
    assert interval is not None and not claim.is_top
    return set(range(interval.lo, interval.hi + 1, interval.stride or 1))


@pytest.mark.parametrize("variant", ("base", "reload"))
def test_guarded_image_address_facts_use_all_original_candidates(variant):
    normalized, unit, keys, expected, image = _normalize(variant)
    view = read_source(normalized, keys["read"])
    assert view is not None and view.image is not None
    # The sealed plan owns the image bytes. Passing no second image to the
    # consumer must not lose their recorded assumption or choose one address.
    for consumer_image in (None, image):
        fact = _facts(normalized, unit, consumer_image)[keys["read"]]
        assert fact.input == 1
        assert _numbers(fact.claim) == {address for _, address, _ in expected}
        assert "readonly-image-data-is-constant" in fact.requires


def test_readonly_off_or_no_sealed_image_port_cannot_invent_an_address_fact(monkeypatch):
    from tdo_v2 import _guarded_image_reads

    normalized, unit, keys, _, image = _normalize()
    assert normalized.memory_graph.image_reads is not None
    disabled = FunctionNormalizer().normalize(unit)
    assert disabled.memory_graph.image_reads is None
    assert keys["read"] not in _facts(disabled, unit)
    # An image object passed only to the consumer is not a substitute for
    # normalization's guarded selector/address proof and sealed graph port.
    assert keys["read"] not in _facts(disabled, unit, image)
    with monkeypatch.context() as without_plan:
        without_plan.setattr(_guarded_image_reads, "derive_guarded_image_reads", lambda *a, **kw: None)
        no_port = FunctionNormalizer().normalize(unit, readonly_image=image)
    assert no_port.memory_graph.image_reads is None
    assert keys["read"] not in _facts(no_port, unit, image)


@pytest.mark.parametrize("variant,options", (("other-selector", {}), ("bypass", {}),
                                           ("base", {"bound": 8}), ("base", {"image_change": "missing"})))
def test_unproved_selector_or_incomplete_domain_has_no_finite_table_fact(variant, options):
    normalized, unit, keys, _, image = _normalize(variant, **options)
    assert read_source(normalized, keys["read"]) is None
    assert keys["read"] not in _facts(normalized, unit, image)


def test_positive_table_values_flow_through_original_arithmetic_to_a_later_load():
    builder, keys = FunctionBuilder(), {}
    flag, wide, scaled, address, signed = (tmp(0x9000, 1), tmp(0x9010), tmp(0x9020),
                                         tmp(0x9030), tmp(0x9040))
    builder.cbranch("done", flag, op("INT_LESS", [const(4, 4), reg(RCX, 4)], flag))
    builder.ins(op("INT_ZEXT", [reg(RCX, 4)], wide))
    builder.ins(op("INT_MULT", [wide, const(4)], scaled))
    builder.ins(add(address, const(DATA_BASE + 0x180), scaled))
    keys["table"] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:LOAD"
    builder.ins(load(reg(RAX, 4), address))
    builder.ins(op("INT_SEXT", [reg(RAX, 4)], signed))
    builder.ins(add(reg(RSI), const(0x500000), signed))
    keys["use"] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:LOAD"
    builder.ins(load(reg(RDX), reg(RSI))).label("done").ret()
    unit, = program_units(builder)
    expected = tuple((selector, DATA_BASE + 0x180 + 4 * selector, 0x10 * (selector + 1))
                     for selector in range(5))
    image = _image(expected)
    normalized = FunctionNormalizer().normalize(unit, readonly_image=image)
    facts = _facts(normalized, unit, image)
    assert _numbers(facts[keys["table"]].claim) == {address for _, address, _ in expected}
    assert _numbers(facts[keys["use"]].claim) == {0x500000 + value for _, _, value in expected}
    assert "readonly-image-data-is-constant" in facts[keys["use"]].requires
    # Original p-code, including its real guard, executes every admitted
    # selector. The downstream memory read is checked by its actual address.
    for selector, _, value in expected:
        vm = Interpreter(unit.observation, constant_space=CONST, seed=selector,
                         image=lambda space, address: image.value(space, address, 1))
        vm.preset(REG, RSP, 8, 0x70000000)
        vm.preset(REG, RCX, 4, selector)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        addresses = {row.offset for row in run.dependencies if row.reader == keys["use"] and row.space_id == RAM}
        assert addresses == set(range(0x500000 + value, 0x500000 + value + 8))


def _local(variant="constant"):
    builder, keys = FunctionBuilder(), {}

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations)-1}:{operations[-1][0]}"
        builder.ins(*operations)

    value = const(0x520000)
    if variant == "source-debt":
        value = tmp(0x9100)
        ins("old_alias", store(reg(RCX), const(0x87654321)))
        ins("source", load(value, reg(RSI)))
    elif variant == "source-call-debt":
        builder.call(0x1f00)
        ins("restore_address", copy(reg(RDI), const(DATA_BASE + 0x300)))
        value = reg(RDX)
    ins("write", store(reg(RDI), value))
    if variant == "partial-write":
        address = tmp(0x9110)
        ins("barrier", add(address, reg(RDI), const(3)), store(address, const(7, 1)))
    elif variant == "call":
        builder.call(0x1f00)
    ins("read", load(reg(RAX), reg(RDI)))
    ins("arithmetic", add(reg(RAX), reg(RAX), const(0x20)))
    ins("use", load(reg(RDX), reg(RAX)))
    builder.ret()
    unit, = program_units(builder)
    return FunctionNormalizer().normalize(unit), unit, keys


def test_local_constant_source_propagates_despite_unknown_target_address():
    normalized, unit, keys = _local()
    view = read_source(normalized, keys["read"])
    assert view is not None and view.local is not None
    # RDI remains an entry pointer, not a numeric address. Its stored bytes
    # nevertheless have an independently proven value and all-path order.
    facts = _facts(normalized, unit)
    assert facts[keys["read"]].claim.single_number() is None
    assert facts[keys["use"]].claim.single_number() == 0x520020
    assert "readonly-image-data-is-constant" not in facts[keys["use"]].requires
    vm = Interpreter(unit.observation, constant_space=CONST, seed=0)
    vm.preset(REG, RSP, 8, 0x70000000)
    vm.preset(REG, RDI, 8, DATA_BASE + 0x300)
    run = vm.run()
    assert run.completed and not vm.opaque_opcodes
    assert {row.offset for row in run.dependencies if row.reader == keys["use"] and row.space_id == RAM} == \
        set(range(0x520020, 0x520028))


@pytest.mark.parametrize("variant", ("partial-write", "call"))
def test_intervening_byte_write_or_call_prevents_stale_constant_propagation(variant):
    normalized, unit, keys = _local(variant)
    view = read_source(normalized, keys["read"])
    assert (view is None) == (variant == "call")
    facts = _facts(normalized, unit)
    if variant == "partial-write":
        # Existing exact memory SSA may reconstruct the overwritten bytes;
        # the new full-width port must not resurrect the earlier constant.
        assert facts[keys["use"]].claim.single_number() == (0x520000 | (7 << 24)) + 0x20
        assert facts[keys["use"]].claim.single_number() != 0x520020
    else:
        assert keys["use"] not in facts


@pytest.mark.parametrize("variant", ("source-debt", "source-call-debt"))
def test_independent_source_value_debt_does_not_become_a_local_numeric_fact(variant):
    normalized, unit, keys = _local(variant)
    view = read_source(normalized, keys["read"])
    if variant == "source-debt":
        assert view is not None and view.local is not None
        assert any(row.operation_key == keys["source"] for row in normalized.may_alias_reads)
    else:
        # The old SSA still names register ENTRY, but the source's actual
        # STORE use is CALL-clobbered. Restoring only its address is no rescue.
        assert view is None
        assert any(row.operation_key == keys["write"] for row in normalized.call_clobber_reads)
    assert keys["use"] not in _facts(normalized, unit)


def test_actual_201_table_fact_and_original_rel32_targets_are_not_whole_function_completion():
    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to the original sealed Suite09 data")
    generation = Path(location) / "tdo_bundles3/v2-win-debug-full/516591db9d11293c0f0b16323bb276fe9f6dd78a68fa322727d80c05d8e0b376"
    unit, image = _actual_unit(generation, 0x140002ec6, "call-names-000074.json")
    key, branch = "1b1:140002ef4:2:LOAD", "1b1:140002f03:0:BRANCHIND"
    normalized = FunctionNormalizer().normalize(unit, readonly_image=image)
    facts = _facts(normalized, unit, image)
    assert _numbers(facts[key].claim) == {0x140007ff0 + selector * 4 for selector in range(5)}
    assert "readonly-image-data-is-constant" in facts[key].requires
    row, = normalized.memory_graph.image_reads.plan.reads
    operations = {f"{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{operation.opcode}": operation
                  for ins in unit.observation.instructions for i, operation in enumerate(ins.operations)}
    original_add = operations["1b1:140002f00:2:INT_ADD"]
    base_copy = operations["1b1:140002ef9:0:COPY"]
    assert original_add.inputs[1] == base_copy.output
    base = base_copy.inputs[0]
    assert base.coordinate.byte_offset == 0x140007ff0
    targets = tuple(_compute("INT_ADD", [base.coordinate.byte_offset,
                        _compute("INT_SEXT", [candidate.value], [4], 8)], [8, 8], 8)
                    for candidate in row.candidates)
    assert targets == (0x140002f05, 0x140002f16, 0x140002f23, 0x140002f34, 0x140002f49)
    record = _record(normalized, unit, "1b1:140002f00:2:INT_ADD")
    image_node, = [node for node in record["nodes"] if "image_read" in node and not node.get("cycle_only")]
    assert tuple(candidate["value"] for candidate in image_node["image_read"]["candidates"]) == \
        tuple(candidate.value for candidate in row.candidates)
    assert "INT_SEXT" in render(record) and "image_read(" in render(record)
    # Numeric intervals over-approximate: the original five image/record
    # alternatives remain distinct, while SEXT+base yields a 69-value range.
    branch_fact = facts[branch]
    assert "readonly-image-data-is-constant" in branch_fact.requires
    assert _numbers(branch_fact.claim) == set(range(0x140002f05, 0x140002f4a))
    assert set(targets) < _numbers(branch_fact.claim)
    assert len(_numbers(branch_fact.claim)) == 69 and len(row.candidates) == 5
    disabled = FunctionNormalizer().normalize(unit)
    off_facts = _facts(disabled, unit)
    assert key not in off_facts and branch not in off_facts
