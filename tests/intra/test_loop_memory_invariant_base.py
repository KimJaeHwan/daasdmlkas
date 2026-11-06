"""Indexed loop addresses retain their original, distinct base snapshots.

The fixture is synthetic. Weak address equations neither allocate memory
nor remove an unknown STORE or a possible interfering different-base write.
"""

from collections import Counter
from dataclasses import replace

import pytest

from pcode_interpreter import Interpreter
from synthetic import (CONST, REG, R8, R9, RAX, RBP, RBX, RCX, RDI, RDX, RSP,
                       FunctionBuilder, add, const, copy, load, op, program_units,
                       reg, store, sub, tmp)
from tdo_v2.function_summary import summarize_function
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
from tdo_v2.operation_records import root_record


def _fixture(variant=None, *, reverse=False, multiplier=1):
    builder, keys = FunctionBuilder(), {}
    index, base, other = reg(RBX), reg(RBP), reg(RDX)
    counter, flag, scaled, address = tmp(0x6000), tmp(0x6100, 1), tmp(0x6200), tmp(0x6300)

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations)-1}:{operations[-1][0]}"
        builder.ins(*operations)

    builder.ins(copy(index, const(0)), copy(counter, reg(R8)))
    if variant == "bypass":
        builder.cbranch("ready", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag))
    if variant == "join-call":
        builder.cbranch("base-right", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag))
        builder.ins(copy(reg(RDI), const(0x50000000))).branch("base-join")
        builder.label("base-right").ins(copy(reg(RDI), const(0x50000000)))
        builder.label("base-join").call(0x1f00)
    ins("base", copy(base, const(0x50000000) if variant == "pre-call" else reg(RDI)))
    if variant == "join-call":
        builder.ins(copy(index, const(0)))
    if variant == "pre-call":
        builder.call(0x1f00)
    if variant == "pre-cycle-call":
        pre_count = tmp(0x6800)
        builder.ins(copy(pre_count, reg(RCX)))
        builder.label("precycle")
        ins("pre-read", copy(tmp(0x6810), base))
        builder.call(0x1f00)
        builder.ins(sub(pre_count, pre_count, const(1)))
        builder.cbranch("precycle", flag, op("INT_NOTEQUAL", [pre_count, const(0)], flag))
    builder.label("ready").ins(copy(other, reg(R9)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag))
    builder.label("loop")
    if variant == "base-write":
        builder.ins(copy(base, reg(R9)))
    if variant == "partial-base":
        builder.ins(copy(reg(RBP, 4), reg(R9, 4)))
    if variant == "call":
        builder.call(0x1f00)

    def indexed(which):
        operands = [const(multiplier), index] if reverse else [index, const(multiplier)]
        if variant == "narrow":
            return (op("INT_MULT", [reg(RBX, 4), const(1, 4)], tmp(0x6200, 4)),
                    op("INT_ZEXT", [tmp(0x6200, 4)], scaled), add(address, which, scaled))
        return op("INT_MULT", operands, scaled), add(address, which, scaled)

    ins("write", *indexed(base), store(address, const(0x11223344, 4)))
    if variant == "other-base":
        ins("interference", *indexed(other), store(address, const(0xaabbccdd, 4)))
    ins("read", *indexed(base), load(reg(RAX, 4), address))
    builder.ins(add(index, index, base if variant == "base-in-stride" else const(8)),
                sub(counter, counter, const(1)))
    builder.cbranch("loop", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
    builder.label("done").ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert type(normalized) is NormalizedFunction
    return normalized, unit, keys


@pytest.mark.parametrize("reverse", (False, True))
def test_unit_scale_and_exact_invariant_base_publish_only_weak_relations(reverse):
    normalized, unit, keys = _fixture(reverse=reverse)
    binding, ssa, graph = normalized.memory_graph.loop_memory, normalized.memory_ssa, normalized.dependencies
    assert binding is not None and len(binding.plan.families) == 1
    family, = binding.plan.families
    base = family.invariant_base
    assert base is not None and (base.span.start, base.span.size) == (RBP, 8)
    definition = ssa.definitions[base.definition_id]
    assert definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.operation_key == keys["base"]
    assert family.stride == 8 and family.span.start == RBX
    assert len(binding.plan.read_from) == 1
    row, = binding.plan.read_from
    assert binding.plan.accesses[row.writer_access].operation_key == keys["write"]
    assert binding.plan.accesses[row.reader_access].operation_key == keys["read"]
    assert any(source == normalized.memory_graph.definition_nodes[base.definition_id]
               and target == binding.family_nodes[0] and edge.kind == "loop_memory_address"
               for source, target, edge in graph.weighted_edges())
    assert any(ssa.actions[item.action_id].operation_key == keys["write"] for item in ssa.unresolved_writes)
    assert any(ssa.actions[item.action_id].operation_key == keys["read"] for item in ssa.unresolved_reads)
    node = graph.node_for_key("op:" + keys["write"])
    record = root_record(normalized, unit, [(node, None)])
    emitted = [item for item in record["nodes"] if item.get("kind") == "op" and item.get("key") == keys["write"]]
    assert emitted
    for item in emitted:
        annotation = item["loop_address"]
        assert annotation["weak"] and annotation["original_memory_debt_retained"]
        assert annotation["invariant_base"]["definition"]["id"] == base.definition_id
        assert annotation["family"] == graph.node(binding.family_nodes[0]).key


@pytest.mark.parametrize("variant", ("base-write", "partial-base", "call", "pre-call", "pre-cycle-call",
                                     "bypass", "base-in-stride", "narrow"))
def test_changed_or_uncertified_base_and_transition_are_refused(variant):
    normalized, _, keys = _fixture(variant)
    binding = normalized.memory_graph.loop_memory
    assert binding is None or not any(a.operation_key == keys["write"] for a in binding.plan.accesses)
    assert any(normalized.memory_ssa.actions[item.action_id].operation_key == keys["write"]
               for item in normalized.memory_ssa.unresolved_writes)


@pytest.mark.parametrize("multiplier", (0, (1 << 64) - 1, 2))
def test_other_multipliers_are_not_unit_scale_identities(multiplier):
    normalized, _, keys = _fixture(multiplier=multiplier)
    binding = normalized.memory_graph.loop_memory
    assert binding is None or not any(a.operation_key == keys["write"] for a in binding.plan.accesses)


def test_call_after_a_reader_visit_is_before_the_next_visit_without_redefining_base():
    from tdo_v2._loop_memory import _Index

    normalized, unit, keys = _fixture("pre-cycle-call")
    index = _Index(normalized.memory_unit, normalized.memory_ssa, unit.observation,
                   unit.scopes.function.entry, unit.scopes.resolution_context)
    writer, reader = keys["base"], keys["pre-read"]
    assert index.region_of.get(index.locations[writer]) is None
    assert index.region_of[index.locations[reader]] in index.call_regions
    assert not index.call_free(writer, reader)


def test_join_sources_cannot_fold_pre_call_constants_into_a_post_call_snapshot():
    normalized, _, keys = _fixture("join-call")
    binding = normalized.memory_graph.loop_memory
    assert binding is not None and len(binding.plan.families) == 1
    family, = binding.plan.families
    assert family.invariant_base is not None
    assert normalized.memory_ssa.definitions[family.invariant_base.definition_id].operation_key == keys["base"]
    assert all(access.offset == 0 for access in binding.plan.accesses)


def test_different_base_families_remain_possible_aliases_even_when_runtime_equal():
    normalized, unit, keys = _fixture("other-base")
    binding = normalized.memory_graph.loop_memory
    assert binding is not None and len(binding.plan.families) == 2
    assert len({family.identity for family in binding.plan.families}) == 2
    assert len({family.invariant_base for family in binding.plan.families}) == 2
    assert len({normalized.dependencies.node(node).semantic_identity for node in binding.family_nodes}) == 2
    assert not binding.plan.read_from
    for second in (0x50000000, 0x50001000):
        vm = Interpreter(unit.observation, constant_space=CONST, seed=0)
        for register, value in ((RSP, 0x70000000), (RDI, 0x50000000), (R9, second), (R8, 2)):
            vm.preset(REG, register, 8, value)
        result = vm.run()
        assert result.completed and not vm.opaque_opcodes
        final = vm.final_bytes()
        actual = sum(final[REG, RAX + i][0] << (8*i) for i in range(4))
        assert actual == (0xaabbccdd if second == 0x50000000 else 0x11223344)


def test_base_identity_is_in_the_issued_receipt_and_revalidated():
    from tdo_v2._loop_memory import validate_loop_memory

    normalized, _, _ = _fixture("other-base")
    plan = normalized.memory_graph.loop_memory.plan
    first, second = plan.families
    altered = replace(first, invariant_base=second.invariant_base)
    with pytest.raises(ValueError, match="unchanged derive result"):
        replace(plan, families=(altered, second))
    bypassed = replace(plan)
    object.__setattr__(bypassed, "families", (altered, second))
    with pytest.raises(ValueError, match="unchanged derive result"):
        validate_loop_memory(bypassed, normalized.memory_ssa)
    validate_loop_memory(plan, normalized.memory_ssa)


def test_base_free_family_keeps_the_original_weak_node_key():
    from dataclasses import fields, make_dataclass
    from hashlib import sha256
    from test_loop_memory_families import _fixture as pointer_fixture

    normalized, _, _ = pointer_fixture()
    binding, ssa = normalized.memory_graph.loop_memory, normalized.memory_ssa
    family, = binding.plan.families
    assert family.invariant_base is None
    previous_fields = [field.name for field in fields(family) if field.name != "invariant_base"]
    PreviousFamily = make_dataclass("LoopMemoryFamily", [(name, object) for name in previous_fields],
                                    frozen=True, slots=True)
    baseline = PreviousFamily(*(getattr(family, name) for name in previous_fields))
    assert repr(family) == repr(baseline)
    identity = sha256(repr(baseline).encode("utf-8")).hexdigest()
    namespace = f"memory-v{ssa.contract_version}:{ssa.function_scope.digest.hex()}:{ssa.unit_digest.hex()}"
    node = normalized.dependencies.node(binding.family_nodes[0])
    assert node.key == f"memory:{namespace}:loop-family:0:{identity}"
    assert node.semantic_identity == identity


def test_weak_family_keeps_original_ssa_edges_debts_and_summary(monkeypatch):
    from tdo_v2 import _loop_memory

    after, unit, _ = _fixture()
    with monkeypatch.context() as patch:
        patch.setattr(_loop_memory, "derive_loop_memory", lambda *args: None)
        before = FunctionNormalizer().normalize(unit)
    assert after.memory_ssa == before.memory_ssa and after.memory_unit == before.memory_unit
    assert after.call_clobber_reads == before.call_clobber_reads
    assert after.may_alias_reads == before.may_alias_reads
    assert after.uncertain_writers == before.uncertain_writers
    def original(graph):
        return Counter((graph.node(a).key, graph.node(b).key, edge)
                       for a, b, edge in graph.weighted_edges() if not edge.kind.startswith("loop_"))
    assert original(after.dependencies) == original(before.dependencies)
    assert summarize_function(after, unit.observation) == summarize_function(before, unit.observation)
