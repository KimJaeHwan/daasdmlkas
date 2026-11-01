"""Explicit graph-owned read ports in records; no fabricated memory inputs."""

from copy import copy as shallow_copy, deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from pcode_interpreter import Interpreter
from synthetic import (CONST, DATA_BASE, RAM, REG, RAX, RCX, RDI, RDX, RSI, RSP,
                       FunctionBuilder, add, const, copy, load, op, program_units, reg, store, tmp)
from test_guarded_image_reads import _image, _normalize
from tdo_v2.configured_naming_contracts import NamingBindingExpectation
from tdo_v2.image_info import ReadOnlyImage, load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.operation_records import Ineligible, eligibility, evaluate, render, root_record


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def _engines(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _record(normalized, unit, key):
    seeds = [(normalized.memory_graph.definition_nodes[i], (definition.span,))
             for i, definition in enumerate(normalized.memory_ssa.definitions) if definition.operation_key == key]
    assert seeds
    return root_record(normalized, unit, seeds)


@pytest.mark.parametrize("variant", ("base", "reload"))
@pytest.mark.parametrize("polarity", ("true", "false"))
@pytest.mark.parametrize("route", ("injected", "stitched"))
def test_image_record_uses_actual_selector_and_success_predicate(variant, polarity, route):
    normalized, unit, keys, expected, _ = _normalize(variant, polarity=polarity)
    record = _record(normalized, unit, keys["read"])
    image_node, = [node for node in record["nodes"] if "image_read" in node]
    assert image_node["memory"] == [] and "debts" not in image_node
    assert image_node["image_read"]["guard"] == keys["guard"]
    assert image_node["image_read"]["condition"]["success_when"] is (polarity == "true")
    assert eligibility(record, route) is None
    for selector, address, value in expected:
        inputs = []

        def entry(node):
            inputs.append(node)
            assert not isinstance(node, tuple)  # never ask caller for invented table RAM
            register = node["register"]
            if register["offset"] == RCX:
                return selector
            if register["offset"] == RSP:
                return 0x70000000
            raise AssertionError(node)

        assert evaluate(record, entry, route=route) == {value}
        assert evaluate(json.loads(json.dumps(record)), entry, route=route) == {value}
        assert inputs
        row = next(c for c in image_node["image_read"]["candidates"] if c["selector"] == selector)
        assert row["address"]["start"] == address
    for selector in (5, 0xffffffff):
        with pytest.raises(Ineligible, match="no alternative"):
            evaluate(record, lambda node: selector if node["register"]["offset"] == RCX else 0x70000000, route=route)
    assert "image_read(" in render(record)


def test_unknown_selector_retains_conditional_candidate_union():
    normalized, unit, keys, expected, _ = _normalize()
    record = _record(normalized, unit, keys["read"])
    assert evaluate(record, lambda _: None) == {value for _, _, value in expected}


def test_two_consumers_share_one_unknown_selector_choice():
    builder = FunctionBuilder()
    flag, wide, address = tmp(0x7000, 1), tmp(0x7010), tmp(0x7020)
    builder.cbranch("done", flag, op("INT_LESS", [const(1, 4), reg(RCX, 4)], flag))
    builder.ins(op("INT_ZEXT", [reg(RCX, 4)], wide), op("INT_MULT", [wide, const(4)], address),
                add(address, const(DATA_BASE + 0x180), address))
    builder.ins(load(reg(RAX, 4), address))
    builder.ins(load(reg(RDX, 4), address))
    key = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:INT_XOR"
    builder.ins(op("INT_XOR", [reg(RAX, 4), reg(RDX, 4)], reg(RAX, 4)))
    builder.label("done").ret()
    unit, = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit, readonly_image=_image(((0, DATA_BASE + 0x180, 7),
                                                                          (1, DATA_BASE + 0x184, 19))))
    record = _record(normalized, unit, key)
    nodes = [node for node in record["nodes"] if "image_read" in node]
    assert len(nodes) == 2
    assert len({node["image_read"]["selection"] for node in nodes}) == 1
    for route in ("injected", "stitched"):
        assert evaluate(record, lambda _: None, route=route) == {0}  # not {0, 7 ^ 19}


def test_image_record_is_explicitly_unsupported_by_the_bv_view_adapter():
    from tdo_v2._record_expression_bv import Adapter
    from tdo_v2._record_expression_views import ViewLimits, select_expression

    normalized, unit, keys, _, _ = _normalize()
    record = _record(normalized, unit, keys["read"])
    adapter = Adapter(record, select_expression(record), ViewLimits(), memory=True)
    with pytest.raises(Ineligible, match="guarded image read"):
        adapter.node(record["root"][0]["node"])


@pytest.mark.parametrize("mutation", ("predicate", "domain", "constant", "condition-polarity"))
def test_malformed_image_annotations_are_not_numeric_licenses(mutation):
    normalized, unit, keys, _, _ = _normalize()
    record = deepcopy(_record(normalized, unit, keys["read"]))
    image = next(node["image_read"] for node in record["nodes"] if "image_read" in node)
    if mutation == "predicate":
        image["condition"]["operand"]["parts"] = []
    elif mutation == "domain":
        image["candidates"][1]["selector"] = image["candidates"][0]["selector"]
    elif mutation == "constant":
        image["candidates"][0]["value"] ^= 1
    else:
        image["condition"]["success_when"] = 0
    assert eligibility(record) is not None
    with pytest.raises(Ineligible):
        evaluate(record, lambda _: 0)


def _local_fixture(*, opaque=False, constant=False, restore_address=False):
    builder = FunctionBuilder()
    if opaque:
        builder.call(0x1f00)
    if restore_address:
        builder.ins(copy(reg(RDI), const(DATA_BASE + 0x300)))
    key = f"1:{builder.entry + (len(builder._rows) + 1) * builder.stride:x}:0:LOAD"
    builder.ins(store(reg(RDI), const(0x1122334455667788) if constant else reg(RDX)))
    builder.ins(load(reg(RAX), reg(RDI))).ret()
    unit, = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    return normalized, unit, key


@pytest.mark.parametrize("constant", (False, True))
def test_local_read_uses_store_operand_bytes_not_unknown_target_ram(constant):
    normalized, unit, key = _local_fixture(constant=constant)
    record = _record(normalized, unit, key)
    local, = [node for node in record["nodes"] if "local_read" in node]
    assert local["key"] == key and "debts" not in local
    assert eligibility(record) is None
    value = 0xfedcba9876543210

    def entry(node):
        assert not isinstance(node, tuple)
        return value if node["register"]["offset"] == RDX else None

    assert evaluate(record, entry) == {0x1122334455667788 if constant else value}


def test_local_source_and_address_call_debts_are_not_removed():
    normalized, unit, key = _local_fixture(opaque=True)
    record = _record(normalized, unit, key)
    assert any(node.get("debts") or node["kind"] == "debt" for node in record["nodes"])
    assert eligibility(record) == "debt"
    with pytest.raises(Ineligible, match="debt"):
        evaluate(record, lambda _: 0)


def test_store_operand_call_debt_survives_when_address_has_been_restored():
    from tdo_v2._memory_read_sources import read_source

    normalized, unit, key = _local_fixture(opaque=True, restore_address=True)
    record = _record(normalized, unit, key)
    # The common issuer refuses the clobbered STORE value-use, despite the
    # register-only SSA still naming ENTRY. The restored address is no rescue.
    assert read_source(normalized, key) is None
    assert not any("local_read" in node for node in record["nodes"])
    assert any(node.get("debts") for node in record["nodes"])
    assert eligibility(record) == "debt"
    with pytest.raises(Ineligible, match="debt"):
        evaluate(record, lambda _: 0)


def _image_context():
    """Real image proof plus independent, valid intrinsic/CALL evidence."""
    builder = FunctionBuilder()
    flag, wide, scaled, address = tmp(0x7200, 1), tmp(0x7210), tmp(0x7220), tmp(0x7230)
    builder.cbranch("done", flag, op("INT_LESS", [const(1, 4), reg(RCX, 4)], flag))
    builder.ins(op("INT_ZEXT", [reg(RCX, 4)], wide))
    builder.ins(op("INT_MULT", [wide, const(4)], scaled))
    builder.ins(add(address, const(DATA_BASE + 0x180), scaled))
    reader = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:LOAD"
    builder.ins(load(reg(RAX, 4), address))
    builder.ins(op("CALLOTHER", [const(483, 4), reg(0x1200, 32), reg(0x1240, 32)], tmp(0x18000, 32)))
    builder.call(0x1f00).ins(copy(reg(RDX), reg(RSI))).label("done").ret()
    unit, = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit, readonly_image=_image(
        ((0, DATA_BASE + 0x180, 7), (1, DATA_BASE + 0x184, 19))))
    assert normalized.memory_graph.image_reads is not None
    assert normalized.call_clobber_reads and normalized.intrinsic_refinements
    original_load = next(operation for instruction in unit.observation.instructions
                         for operation in instruction.operations
                         if instruction.address.byte_offset == int(reader.split(":")[1], 16))
    return normalized, unit, reader, original_load


def _context_change(normalized, reader, original_load, change):
    candidate = normalized.memory_graph.image_reads.plan.reads[0].candidates[0]
    wild = normalized.wild_objects
    return {
        "memory-identity": {"memory_unit": replace(normalized.memory_unit)},
        "wild-objects": {"wild_objects": wild ^ frozenset((candidate.span.object_id,))},
        "call-clobbers": {"call_clobber_reads": (), "call_clobber_debts": ()},
        # A well-typed original operation still changes the policy-key set;
        # its value must not be interpreted using a previously issued proof.
        "override-keys": {"operation_overrides": ((reader, original_load),)},
        # Remove a genuine derived intrinsic, rather than injecting a fake
        # refinement type that some unrelated type check would reject first.
        "intrinsic-keys": {"intrinsic_refinements": ()},
        "readonly-off": {"assumes_readonly_image_constant": False},
    }[change]


@pytest.mark.parametrize("change", ("memory-identity", "wild-objects", "call-clobbers",
                                    "override-keys", "intrinsic-keys", "readonly-off"))
def test_image_authority_rejects_changed_original_context_with_the_same_ssa(change):
    normalized, _, reader, original_load = _image_context()
    changes = _context_change(normalized, reader, original_load, change)
    assert "memory_ssa" not in changes
    if change == "memory-identity":
        assert changes["memory_unit"] == normalized.memory_unit
        assert changes["memory_unit"] is not normalized.memory_unit
    with pytest.raises(ValueError, match="readonly-image|image reads require unchanged"):
        replace(normalized, **changes)


@pytest.mark.parametrize("change", ("memory-identity", "wild-objects", "call-clobbers",
                                    "override-keys", "intrinsic-keys", "readonly-off"))
def test_image_consumer_rechecks_original_context_after_bypassing_construction(change):
    from tdo_v2._memory_read_sources import read_source

    normalized, unit, reader, original_load = _image_context()
    assert read_source(normalized, reader).image is not None
    # Adversarial mutation of an exact normal object tests the consumer's
    # own guard independently of dataclass construction. No forged proof,
    # substitute object type, graph, or SSA is introduced.
    changed = shallow_copy(normalized)
    for name, value in _context_change(normalized, reader, original_load, change).items():
        object.__setattr__(changed, name, value)
    assert changed.memory_ssa is normalized.memory_ssa
    with pytest.raises(ValueError, match="image reads require unchanged"):
        read_source(changed, reader)
    with pytest.raises(ValueError, match="image reads require unchanged"):
        _record(changed, unit, reader)


def _actual_unit(generation, entry, member):
    names = json.loads((generation / member).read_bytes())
    binding = NamingBindingExpectation(bytes.fromhex(names["exporter_source_sha256"]), names["ghidra_version"])
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        unit = next(row.unit for row in session.iter_functions() if row.unit.scopes.function.entry.byte_offset == entry)
    return unit, ReadOnlyImage(generation, load_image_info(generation))


def _data():
    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to the original sealed corpus/Suite09 data")
    return Path(location)


def test_actual_sw_dense_eight_values_match_original_pcode():
    generation = _data() / "tdo_bundles3/corpus/clang-x64-O2/5b842e47c166208cde4cfa22d6ce95cf534731f36df8b99412ed0e45ac0d14c8"
    unit, readonly = _actual_unit(generation, 0x101b10, "call-names-000023.json")
    normalized = FunctionNormalizer().normalize(unit, readonly_image=readonly)
    record = _record(normalized, unit, "1b1:101b23:2:LOAD")
    assert len(next(node["image_read"] for node in record["nodes"] if "image_read" in node)["candidates"]) == 8
    expected = (11, 23, 14, 5, 104, 0xfffffff7, 48, 77)
    for selector in (*range(8), 8, 0xffffffff):
        vm = Interpreter(unit.observation, constant_space=48, seed=selector,
                         image=lambda space, address: readonly.value(space, address, 1))
        vm.preset(548, 0x20, 8, 0x70000000)
        vm.preset(548, 0x38, 4, selector)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        value = vm._peek(548, 0, 4)[0]
        if selector < 8:
            assert evaluate(record, lambda node: selector if node["register"]["offset"] == 0x38 else 0x70000000) == {value}
        else:
            with pytest.raises(Ineligible, match="no alternative"):
                evaluate(record, lambda node: selector if node["register"]["offset"] == 0x38 else 0x70000000)
        assert value == (expected[selector] if selector < 8 else 0xffffffff)


def test_actual_201_record_exposes_five_rel32_alternatives_and_original_arithmetic():
    generation = _data() / "tdo_bundles3/v2-win-debug-full/516591db9d11293c0f0b16323bb276fe9f6dd78a68fa322727d80c05d8e0b376"
    unit, readonly = _actual_unit(generation, 0x140002ec6, "call-names-000074.json")
    normalized = FunctionNormalizer().normalize(unit, readonly_image=readonly)
    record = _record(normalized, unit, "1b1:140002f00:2:INT_ADD")
    image, = [node["image_read"] for node in record["nodes"] if "image_read" in node and not node.get("cycle_only")]
    assert [candidate["value"] for candidate in image["candidates"]] == [0xffffaf15, 0xffffaf26, 0xffffaf33, 0xffffaf44, 0xffffaf59]
    assert any(node.get("key") == "1b1:140002ef7:0:INT_SEXT" for node in record["nodes"])
    assert "image_read(" in render(record) and "INT_SEXT" in render(record)
    assert eligibility(record) is not None  # cyclic dispatcher is not a numeric whole-function proof
