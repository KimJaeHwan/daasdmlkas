"""Loop address families explain possible memory effects, never exact kills.

Concrete runs use the existing interpreter; the graph oracle intentionally
does not stand in for an occurrence proof (it records static writer keys).
"""

from collections import Counter
from dataclasses import FrozenInstanceError, replace

import pytest

from graph_oracle import check
from pcode_interpreter import Entry, Interpreter
from synthetic import (
    CONST, DATA_BASE, RAM, REG, R8, R9, RAX, RBX, RCX, RDI, RDX, RSP,
    FunctionBuilder, add, const, copy, load, op, program_units, reg, store, sub, tmp,
)
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


MODULUS, BASE, SLOT = 1 << 64, 0x50000000, DATA_BASE
VECTOR, SCALAR, SENTINEL = 0x1122334455667788, 0x99aabbcc, 0xe1e2e3e4e5e6e7e8


def _fixture(*, chain=False, variant=None, stride=16, width=16, return_unit=False):
    builder, loops = FunctionBuilder(), []
    pointer = reg(RBX)
    builder.ins(load(pointer, const(SLOT)))

    def emit_loop(index, step, widths_offsets, source, *, post=False, pair=False):
        tag, keys = f"loop{index}", {}
        counter, flag, address = tmp(0x4000 + index * 0x100), tmp(0x7000 + index * 0x100, 1), tmp(0x8000)

        def ins(name, *operations):
            ordinal = len(operations) - 1
            keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{ordinal}:{operations[-1][0]}"
            builder.ins(*operations)

        builder.ins(copy(counter, reg(source))).cbranch(tag + "done", flag,
                         op("INT_EQUAL", [counter, const(0)], flag))
        if pair:
            ins("entry", add(pointer, pointer, const(16)))
        header = f"1:{builder.entry + len(builder._rows) * builder.stride:x}"
        builder.label(tag)
        if variant in ("continue", "skip-update"):
            builder.cbranch(tag + ("advance" if variant == "continue" else "latch"), flag,
                            op("INT_EQUAL", [counter, const(2)], flag))
        if variant == "ambiguous-phase":
            builder.cbranch(tag + "other", flag, op("INT_EQUAL", [counter, const(2)], flag))
            builder.ins(copy(address, pointer)).branch(tag + "write")
            builder.label(tag + "other").ins(add(address, pointer, const(step)))
            builder.label(tag + "write")
            ins("store0", store(address, const(VECTOR, width)))
        elif post:
            ins("store0", copy(address, pointer), add(pointer, pointer, const(step)),
                store(address, const(VECTOR, width)))
            keys["update"] = keys["store0"].rsplit(":", 2)[0] + ":1:INT_ADD"
        else:
            for number, (access_width, offset) in enumerate(widths_offsets):
                value = counter if variant == "previous" else const(SCALAR if access_width == 4 else VECTOR,
                                                                    access_width)
                if offset:
                    ins(f"store{number}", add(address, pointer, const(offset % MODULUS)), store(address, value))
                else:
                    ins(f"store{number}", store(pointer, value))
        if variant == "partial":
            ins("read", load(reg(RAX), pointer))
        elif variant == "previous":
            ins("read", sub(address, pointer, const(step)), load(reg(RAX), address))
        elif variant == "alias":
            ins("alias", store(reg(RDI), const(0x5a, 1)))
            ins("read", load(reg(RAX), pointer))
        elif variant == "call":
            builder.call(0x1f00)
        if not post:
            builder.label(tag + "advance")
            if variant == "partial-pointer":
                ins("partial", copy(reg(RBX, 4), reg(RDX, 4)))
            ins("update", add(pointer, pointer, const(step)))
            if variant == "two-updates":
                ins("update2", add(pointer, pointer, const(step)))
        builder.label(tag + "latch").ins(sub(counter, counter, const(1)))
        latch = f"1:{builder.entry + len(builder._rows) * builder.stride:x}"
        builder.cbranch(tag, flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
        if pair:
            ins("exit", sub(pointer, pointer, const(16)))
        builder.label(tag + "done")
        loops.append(dict(header=header, latch=latch, stride=step, accesses=widths_offsets, keys=keys))

    if chain:
        emit_loop(0, 16, ((16, 0),), RCX, post=True)
        emit_loop(1, 32, ((16, -16), (16, 0)), R8, pair=True)
        emit_loop(2, 4, ((4, 0),), R9)
    elif variant == "same-stride":
        emit_loop(0, stride, ((width, 0),), RCX)
        # The second loop deliberately starts at the same concrete address.
        # Equal bases/steps do not merge two loop occurrences or prove no alias.
        builder.ins(load(pointer, const(SLOT)))
        emit_loop(1, stride, ((width, 0),), R8)
        loops[-1]["after_read"] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:LOAD"
        builder.ins(load(reg(RAX), const(BASE)))
    else:
        emit_loop(0, stride, ((width, 0),), RCX)
    builder.ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit if return_unit else unit.observation, loops


def _binding(normalized):
    binding = normalized.memory_graph.loop_memory
    assert binding is not None and binding.plan.families and binding.plan.accesses
    assert len(binding.family_nodes) == len(binding.plan.families)
    assert len(binding.access_nodes) == len(binding.plan.accesses)
    return binding


def _accesses(normalized, keys):
    binding = normalized.memory_graph.loop_memory
    return [] if binding is None else [(binding, index, row) for index, row in enumerate(binding.plan.accesses)
                                     if row.operation_key in keys]


def _edge(graph, source, target, kind):
    assert any(t == target and edge.kind == kind for _, t, edge in graph.out_edges(source))


def _weak_access(normalized, binding, index, access):
    ssa, graph, memory = normalized.memory_ssa, normalized.dependencies, normalized.memory_graph
    family = binding.plan.families[access.family_index]
    family_node, access_node = binding.family_nodes[access.family_index], binding.access_nodes[index]
    operation_node = graph.node_for_key("op:" + access.operation_key)
    assert graph.node(family_node).kind is NodeKind.EFFECT
    assert graph.node(access_node).kind is NodeKind.EFFECT
    assert graph.node(family_node).label == "loop_address_family"
    assert graph.node(access_node).label == "loop_possible_memory_" + access.direction
    _edge(graph, family_node, access_node, "loop_memory_address")
    _edge(graph, memory.definition_nodes[access.address_definition_id], access_node, "loop_memory_address")
    _edge(graph, family_node, operation_node, "loop_memory_address")
    assert ssa.definitions[access.address_definition_id].span.contains(access.address_span)
    assert family.span.size == 8 and family.address_bits == 64
    assert family.stride in (4, 16, 32)
    assert family.entry_edges and family.backedge_edges
    for edge in family.entry_edges:
        assert edge.block_key == family.header and edge.span == family.span
        assert edge.predecessor_key not in family.blocks
        for definition_id in edge.definition_ids:
            assert ssa.definitions[definition_id].span.contains(edge.span)
            _edge(graph, memory.definition_nodes[definition_id], family_node, "loop_memory_address")
    transition = ssa.definitions[family.transition_definition_id]
    assert transition.kind is MemoryDefinitionKind.DATA_WRITE and transition.span == family.span
    _edge(graph, memory.definition_nodes[family.transition_definition_id], family_node, "loop_memory_address")
    occurrences = ssa.unresolved_writes if access.direction == "write" else ssa.unresolved_reads
    debts = memory.unresolved_write_nodes if access.direction == "write" else memory.unresolved_read_nodes
    (debt,) = [node for occurrence, node in zip(occurrences, debts)
               if ssa.actions[occurrence.action_id].operation_key == access.operation_key
               and occurrence.access.width == access.width]
    if access.direction == "write":
        (action,) = [row for row in ssa.actions if row.operation_key == access.operation_key]
        # A family is not one exact target byte span and cannot kill memory.
        assert not action.write_definition_ids
        _edge(graph, operation_node, access_node, "loop_possible_write")
        _edge(graph, access_node, debt, "loop_possible_write")
        _edge(graph, operation_node, debt, "unresolved_write")
    else:
        _edge(graph, debt, access_node, "loop_possible_read")
        _edge(graph, access_node, operation_node, "loop_possible_read")
        _edge(graph, debt, operation_node, "unresolved_read")


def _image(base, stride=16):
    def byte(space, address):
        if space == RAM and SLOT <= address < SLOT + 8:
            return (base >> (8 * (address - SLOT))) & 0xff
        for start in (base, (base - stride) % MODULUS):
            if space == RAM and start <= address < start + 8:
                return (SENTINEL >> (8 * (address - start))) & 0xff
        return None
    return byte


def _execute(observation, counts, *, base=BASE, stride=16, havoc=False):
    interpreter = Interpreter(observation, constant_space=CONST, seed=0, image=_image(base, stride),
                              havoc_calls=(REG, RSP, 8) if havoc else None)
    for register, value in {RSP: 0x70000000, RCX: counts[0], R8: counts[1], R9: counts[2],
                            RDI: base, RDX: 0x12345678}.items():
        interpreter.preset(REG, register, 8, value)
    run = interpreter.run()
    assert run.completed and not interpreter.opaque_opcodes
    return interpreter, run


def _ram_written(interpreter, store_keys):
    return {address: value for (space, address), (value, writer, _) in interpreter.final_bytes().items()
            if space == RAM and writer in store_keys}


def _put(memory, address, width, value):
    for byte in range(width):
        memory[(address + byte) % MODULUS] = (value >> (8 * byte)) & 0xff


def _oracle(normalized, observation, counts, *, base=BASE, stride=16, havoc=False):
    report = check(normalized, observation, seeds=range(len(counts)), image=_image(base, stride),
                   register_pools=lambda seed: {RSP: 0x70000000, RCX: counts[seed][0],
                                                R8: counts[seed][1], R9: counts[seed][2],
                                                RDI: base, RDX: 0x12345678},
                   havoc_calls=(REG, RSP, 8) if havoc else None)
    assert report.runs == len(counts) and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_three_sequential_loops_keep_header_snapshots_and_all_four_weak_stores(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, loops = _fixture(chain=True)
    binding = _binding(normalized)
    used = []
    for loop in loops:
        keys = {loop["keys"][f"store{number}"] for number in range(len(loop["accesses"]))}
        rows = _accesses(normalized, keys)
        assert len(rows) == len(loop["accesses"])
        indices = {row.family_index for _, _, row in rows}
        assert len(indices) == 1
        family_index, = indices
        used.append(family_index)
        family = binding.plan.families[family_index]
        assert family.header == loop["header"] and family.latch == loop["latch"]
        assert family.stride == loop["stride"]
        assert {(row.width, row.offset) for _, _, row in rows} == {
            (width, offset % MODULUS) for width, offset in loop["accesses"]}
        for _, index, row in rows:
            _weak_access(normalized, binding, index, row)
    assert len(set(used)) == 3
    snapshots = [tuple((edge.predecessor_key, edge.definition_ids) for edge in
                       binding.plan.families[index].entry_edges) for index in used]
    assert len(set(snapshots)) == 3
    entry_writers = [{normalized.memory_ssa.definitions[identifier].operation_key
                      for edge in binding.plan.families[index].entry_edges
                      for identifier in edge.definition_ids} for index in used]
    assert entry_writers[0] == {"1:1000:0:LOAD"}
    assert entry_writers[1] == {loops[1]["keys"]["entry"]}
    # The scalar loop follows either zero vector iterations, only the first
    # loop, or both vector loops. Preserve all three actual incoming values.
    assert entry_writers[2] == {"1:1000:0:LOAD", loops[0]["keys"]["update"], loops[1]["keys"]["exit"]}
    cases = ((0, 0, 0), (1, 1, 1), (3, 2, 3), (0, 2, 1), (2, 0, 1))
    store_keys = {row.operation_key for row in binding.plan.accesses if row.direction == "write"}
    for counts in cases:
        interpreter, run = _execute(observation, counts)
        expected, pointer = {}, BASE
        for _ in range(counts[0]):
            _put(expected, pointer, 16, VECTOR)
            pointer += 16
        for _ in range(counts[1]):
            _put(expected, pointer, 16, VECTOR)
            _put(expected, pointer + 16, 16, VECTOR)
            pointer += 32
        for _ in range(counts[2]):
            _put(expected, pointer, 4, SCALAR)
            pointer += 4
        assert _ram_written(interpreter, store_keys) == expected
        if not any(counts):
            assert not set(run.executed) & store_keys
    _oracle(normalized, observation, cases)


def test_continue_uses_header_occurrence_not_dense_store_occurrence():
    normalized, observation, (loop,) = _fixture(variant="continue")
    rows = _accesses(normalized, {loop["keys"]["store0"]})
    assert len(rows) == 1
    binding, index, row = rows[0]
    _weak_access(normalized, binding, index, row)
    interpreter, run = _execute(observation, (3, 0, 0))
    expected = {}
    for displacement in (0, 32):  # second header visit skipped STORE, not pointer advance
        _put(expected, BASE + displacement, 16, VECTOR)
    assert _ram_written(interpreter, {row.operation_key}) == expected
    assert run.executed.count(row.operation_key) == 2
    _oracle(normalized, observation, ((0, 0, 0), (1, 0, 0), (3, 0, 0)))


@pytest.mark.parametrize("variant", ("skip-update", "two-updates", "partial-pointer", "call", "ambiguous-phase"))
def test_nonuniform_or_unproved_recurrences_never_get_a_family_access(variant):
    normalized, observation, (loop,) = _fixture(variant=variant)
    key = loop["keys"]["store0"]
    assert not _accesses(normalized, {key})
    assert any(normalized.memory_ssa.actions[row.action_id].operation_key == key
               for row in normalized.memory_ssa.unresolved_writes)
    _oracle(normalized, observation, ((1, 0, 0), (3, 0, 0)), havoc=variant == "call")


def test_partial_store_does_not_define_or_kill_the_unwritten_load_bytes():
    normalized, observation, (loop,) = _fixture(variant="partial", width=4)
    keys = {loop["keys"]["store0"], loop["keys"]["read"]}
    rows = _accesses(normalized, keys)
    assert {(row.direction, row.width, row.offset) for _, _, row in rows} == {("write", 4, 0), ("read", 8, 0)}
    for binding, index, row in rows:
        _weak_access(normalized, binding, index, row)
    interpreter, run = _execute(observation, (1, 0, 0))
    dependencies = [dependency for dependency in run.dependencies
                    if dependency.reader == loop["keys"]["read"] and dependency.space_id == RAM]
    assert {dependency.offset for dependency in dependencies if isinstance(dependency.writer, Entry)} == \
        set(range(BASE + 4, BASE + 8))
    final = interpreter.final_bytes()
    value = sum(final[(REG, RAX + byte)][0] << (8 * byte) for byte in range(8))
    assert value == (SENTINEL & 0xffffffff00000000) | SCALAR
    _oracle(normalized, observation, ((1, 0, 0), (3, 0, 0)))


def test_previous_iteration_load_keeps_initial_memory_and_prior_occurrence_possible():
    normalized, observation, (loop,) = _fixture(variant="previous", width=8)
    rows = _accesses(normalized, {loop["keys"]["store0"], loop["keys"]["read"]})
    assert {(row.direction, row.offset) for _, _, row in rows} == {("write", 0), ("read", MODULUS - 16)}
    for binding, index, row in rows:
        _weak_access(normalized, binding, index, row)
    for count, expected in ((1, SENTINEL), (3, 2)):
        interpreter, run = _execute(observation, (count, 0, 0))
        final = interpreter.final_bytes()
        assert sum(final[(REG, RAX + byte)][0] << (8 * byte) for byte in range(8)) == expected
        dependencies = [dependency for dependency in run.dependencies
                        if dependency.reader == loop["keys"]["read"] and dependency.space_id == RAM]
        assert any(isinstance(dependency.writer, Entry) for dependency in dependencies)
        if count > 1:
            assert any(dependency.writer == loop["keys"]["store0"] for dependency in dependencies)
    _oracle(normalized, observation, ((0, 0, 0), (1, 0, 0), (3, 0, 0)))


def test_same_stride_and_equal_concrete_bases_do_not_merge_distinct_loops():
    normalized, observation, loops = _fixture(variant="same-stride")
    keys = {loop["keys"]["store0"] for loop in loops}
    rows = _accesses(normalized, keys)
    assert len(rows) == 2 and len({row.family_index for _, _, row in rows}) == 2
    assert len({binding.plan.families[row.family_index].header for binding, _, row in rows}) == 2
    for binding, index, row in rows:
        _weak_access(normalized, binding, index, row)
    graph = normalized.dependencies
    reader = graph.node_for_key("op:" + loops[-1]["after_read"])
    reachable = graph.backward_reachable((reader,))
    assert all(graph.node_for_key("op:" + key) in reachable for key in keys)
    _oracle(normalized, observation, ((1, 1, 0), (3, 2, 0), (0, 1, 0)))


def test_wrap_is_a_modular_weak_effect_not_one_linear_exact_memory_span():
    normalized, observation, (loop,) = _fixture()
    (binding, index, row), = _accesses(normalized, {loop["keys"]["store0"]})
    _weak_access(normalized, binding, index, row)
    base = MODULUS - 8
    for count in (0, 1, 3):
        interpreter, _ = _execute(observation, (count, 0, 0), base=base)
        expected = {}
        for visit in range(count):
            _put(expected, base + 16 * visit, 16, VECTOR)
        assert _ram_written(interpreter, {row.operation_key}) == expected
    _oracle(normalized, observation, ((0, 0, 0), (1, 0, 0), (3, 0, 0)), base=base)


def test_alias_writes_do_not_disappear_when_the_other_address_gets_a_family():
    normalized, observation, (loop,) = _fixture(variant="alias", width=8)
    rows = _accesses(normalized, {loop["keys"]["store0"], loop["keys"]["read"]})
    assert len(rows) == 2
    for binding, index, row in rows:
        _weak_access(normalized, binding, index, row)
    graph = normalized.dependencies
    writer, reader = (graph.node_for_key("op:" + loop["keys"][name]) for name in ("alias", "read"))
    assert writer in graph.backward_reachable((reader,))
    interpreter, _ = _execute(observation, (1, 0, 0))
    final = interpreter.final_bytes()
    assert sum(final[(REG, RAX + byte)][0] << (8 * byte) for byte in range(8)) == (VECTOR & ~0xff) | 0x5a
    _oracle(normalized, observation, ((1, 0, 0), (3, 0, 0)))


@pytest.mark.parametrize("variant", (None, "previous", "alias"))
def test_weak_family_graph_addition_preserves_exact_ssa_summary_and_load_identity(monkeypatch, variant):
    from tdo_v2 import _loop_memory
    from tdo_v2._load_identity import prepare_load_identities
    from tdo_v2.function_summary import summarize_function
    from tdo_v2.interprocedural import AnalyzedFunction

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    after, unit, _ = _fixture(chain=variant is None, variant=variant, width=8, return_unit=True)
    assert after.memory_graph.loop_memory is not None
    with monkeypatch.context() as disabled:
        disabled.setattr(_loop_memory, "derive_loop_memory", lambda *args: None)
        before = FunctionNormalizer().normalize(unit)
    assert isinstance(before, NormalizedFunction) and before.memory_graph.loop_memory is None
    assert after.memory_ssa == before.memory_ssa
    assert after.memory_unit == before.memory_unit
    assert after.may_alias_reads == before.may_alias_reads
    assert after.call_clobber_reads == before.call_clobber_reads
    assert after.uncertain_writers == before.uncertain_writers
    assert after.load_value_proofs == before.load_value_proofs == ()
    assert after.forward_memory_proofs == before.forward_memory_proofs

    def original_edges(graph):
        return Counter((graph.node(source).key, graph.node(target).key, edge)
                       for source, target, edge in graph.weighted_edges()
                       if edge.kind not in ("loop_memory_address", "loop_possible_read", "loop_possible_write",
                                            "loop_read_from", "loop_read_from_value", "loop_read_from_witness",
                                            "loop_previous_read_from", "loop_previous_read_from_value"))

    assert original_edges(after.dependencies) == original_edges(before.dependencies)
    summaries = [summarize_function(normalized, unit.observation) for normalized in (before, after)]
    assert summaries[0] == summaries[1]
    assert summaries[0].premise_uses == summaries[1].premise_uses
    for normalized, summary in zip((before, after), summaries):
        assert normalized.forward_inputs is not None
        result = AnalyzedFunction("1:1000", unit, normalized, summary)
        assert prepare_load_identities(result, {}) is None


@pytest.mark.parametrize("change", ("stride", "offset", "space", "family-index", "entry-reference"))
@pytest.mark.parametrize("consumer", ("constructor", "validator"))
def test_loop_plan_seal_rejects_changed_public_evidence(change, consumer):
    from tdo_v2._loop_memory import validate_loop_memory

    normalized, _, _ = _fixture(chain=True)
    plan = _binding(normalized).plan
    validate_loop_memory(plan, normalized.memory_ssa)
    if change in ("stride", "entry-reference"):
        family = plan.families[0]
        if change == "stride":
            changed = replace(family, stride=17)
        else:
            # A well-typed but different existing SSA source, not an invalid
            # id or malformed header. The issued payload must not be mutable.
            entry = replace(family.entry_edges[0],
                            definition_ids=plan.families[1].entry_edges[0].definition_ids)
            changed = replace(family, entry_edges=(entry, *family.entry_edges[1:]))
        payload = {"families": (changed, *plan.families[1:])}
    else:
        first = plan.accesses[0]
        field, value = {"offset": ("offset", 123), "space": ("space_id", 999),
                        "family-index": ("family_index", (first.family_index + 1) % len(plan.families))}[change]
        payload = {"accesses": (replace(first, **{field: value}), *plan.accesses[1:])}
    if consumer == "constructor":
        with pytest.raises(ValueError, match="unchanged derive result"):
            replace(plan, **payload)
    else:
        altered = replace(plan)
        # Simulate a consumer receiving an object that bypassed __init__;
        # validation must independently check the immutable issued payload.
        for field, value in payload.items():
            object.__setattr__(altered, field, value)
        with pytest.raises(ValueError, match="unchanged derive result"):
            validate_loop_memory(altered, normalized.memory_ssa)
    validate_loop_memory(plan, normalized.memory_ssa)


def test_loop_plan_authority_pins_original_immutable_inputs_not_just_equal_ssa_content(monkeypatch):
    from tdo_v2._loop_memory import LoopMemoryPlan, validate_loop_memory

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    normalized, unit, _ = _fixture(chain=True, return_unit=True)
    plan = _binding(normalized).plan
    proof = plan._proof
    assert proof is not None and proof.ssa is normalized.memory_ssa
    assert normalized.forward_inputs is not None
    # scopes.resolution_context constructs an equivalent context per access;
    # forward_inputs retains the actual context used by this normalization.
    expected_inputs = (normalized.memory_unit, unit.observation, unit.scopes.function.entry,
                       normalized.forward_inputs.context, unit.scopes.program.evidence.address_spaces,
                       unit.scopes.program.evidence.translation_namespace)
    assert len(proof.inputs) == len(expected_inputs)
    assert all(actual is expected for actual, expected in zip(proof.inputs, expected_inputs))
    with pytest.raises(FrozenInstanceError):
        proof.payload = ()
    with pytest.raises(ValueError, match="unchanged derive result"):
        LoopMemoryPlan(plan.function_scope, plan.unit_digest, plan.families, plan.accesses)
    equivalent = replace(normalized.memory_ssa)
    assert equivalent == normalized.memory_ssa and equivalent is not normalized.memory_ssa
    with pytest.raises(ValueError, match="original SSA identity"):
        validate_loop_memory(plan, equivalent)
    validate_loop_memory(plan, normalized.memory_ssa)


def test_loop_plan_snapshot_retains_public_evidence_but_cannot_reauthorize_it():
    import json

    from tools.graph_fidelity.semantic_snapshot import CONTRACT, encode
    from tdo_v2._loop_memory import LoopMemoryPlan

    normalized, _, _ = _fixture(chain=True)
    plan = _binding(normalized).plan
    public = {field: getattr(plan, field) for field in ("function_scope", "unit_digest", "families", "accesses")}
    assert plan.read_from == ()  # An absent/default relation preserves old snapshots.
    encoded = json.loads(json.dumps(encode(plan)))
    assert encoded == {"type": "LoopMemoryPlan", **{field: encode(value) for field, value in public.items()}}
    _, excluded = CONTRACT["LoopMemoryPlan"]
    assert set(excluded) == {"_proof"} and excluded["_proof"]
    assert "_proof" not in encoded
    # Even correctly typed public objects (stronger than the JSON dicts)
    # matching every serialized field carry no process-local authority.
    with pytest.raises(ValueError, match="unchanged derive result"):
        LoopMemoryPlan(**public)
