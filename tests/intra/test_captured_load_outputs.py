"""A rejected memory-content substitution is not a rejected raw LOAD output.

The original observed operations and SSA remain the evidence. A once-only
LOAD may name its own captured value, never rescue its former content or
claim that different LOAD occurrences read equal values.
"""

from dataclasses import replace

import pytest

from graph_oracle import check
from synthetic import (
    DATA_BASE, RAM, RAX, RBX, RDI, RDX, RSP, FunctionBuilder, const, load, op,
    program_units, reg, store, tmp,
)
from tdo_v2.call_summary_effects import AnchoredSpan, ProvenCallEffect, ProvenRunEffect
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction, _ScopedNormalizer
from tdo_v2.pcode_blocks import build_pcode_block_graph
from tdo_v2.relative_memory import (
    _configured_projector, _operation_key, _unsettled_reads,
    single_execution_blocks, single_execution_keys,
)
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind


SLOT, OLD_ADDRESS = DATA_BASE, DATA_BASE + 0x100


def _fixture(*, second=False, loop=False, debt=None):
    builder, keys = FunctionBuilder(), {}
    pointer, other = tmp(0x100), tmp(0x200)

    def ins(name, *operations):
        ordinal = len(operations) - 1
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{ordinal}:{operations[-1][0]}"
        builder.ins(*operations)

    ins("slot", store(const(SLOT), const(OLD_ADDRESS)))
    if debt == "alias":
        ins("alias", store(reg(RBX), reg(RDI)))
    if debt == "pending":
        ins("pending", op("INT_DIV", [reg(RDI), reg(RDX)], other), store(other, reg(RBX)))
    if loop:
        builder.label("again")
    ins("capture", load(pointer, const(SLOT)))
    if second:
        ins("capture2", load(other, const(SLOT)))
    ins("store", store(pointer, reg(RDX)))
    if debt == "call":
        builder.call(0x1f00)
    ins("read", load(reg(RAX), pointer))
    if loop:
        builder.cbranch("again", reg(RDI, 1))
    builder.ret()
    (unit,) = program_units(builder)
    return unit, keys


def _projector(unit, *, normalized=None):
    normalized = FunctionNormalizer().normalize(unit) if normalized is None else normalized
    assert isinstance(normalized, NormalizedFunction)
    inputs, observation = normalized.forward_inputs, unit.observation
    assert inputs is not None
    operations = {_operation_key(instruction.address, ordinal, operation): operation
                  for instruction in observation.instructions
                  for ordinal, operation in enumerate(instruction.operations)}
    graph = build_pcode_block_graph(observation, unit.scopes.function.entry)
    projector = _configured_projector(
        inputs.effect_unit, observation, inputs.context, inputs.address_spaces,
        normalized.memory_ssa, operations, unit.scopes.program.evidence.translation_namespace.language_id,
        once_keys=single_execution_keys(observation, graph),
        once_blocks=single_execution_blocks(observation, graph),
        pointer_rows=dict(normalized.pointer_rows),
    )
    return projector, normalized


def _definition(normalized, key):
    (definition,) = [row for row in normalized.memory_ssa.definitions
                     if row.operation_key == key and row.kind is MemoryDefinitionKind.DATA_WRITE]
    return definition


def _memory_reads(normalized, key):
    ssa = normalized.memory_ssa
    return [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == key
            and row.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)]


@pytest.fixture(autouse=True)
def _retain_forward_inputs(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def test_blocked_content_stays_unavailable_but_the_exact_load_output_is_a_wild_identity():
    unit, keys = _fixture()
    projector, normalized = _projector(unit)
    definition = _definition(normalized, keys["capture"])
    content = projector._expression_from_memory_read(keys["capture"], 8)
    assert content is not None and not content.atoms and content.displacement == OLD_ADDRESS
    projector._blocked = frozenset({keys["capture"]})
    assert projector._expression_from_memory_read(keys["capture"], 8) is None
    projector._fresh_windows[keys["capture"]] = (32, "test-only-never-null")
    captured = projector._definition_atom(definition, definition.span, eligible=True)
    assert captured is not None and captured.atoms and captured != content
    (atom, coefficient), = captured.atoms
    assert coefficient == 1 and captured.displacement == 0 and captured.byte_size == 8
    assert atom in projector._definition_atoms and projector._is_stack_derived(atom)
    assert atom in projector.ineligible_atoms and atom not in projector._eligible_atoms
    assert atom not in projector._fresh_atoms and atom not in projector._nonstack_atoms
    assert atom not in projector._nonstack_extent and atom not in projector._allocator_atoms
    assert atom not in projector._guarded_atoms
    object_id = projector._relative_object(captured, RAM, width=8)
    assert object_id in projector.wild_objects
    assert object_id not in projector.fresh_objects and object_id not in projector.nonstack_objects
    assert not projector.nonstack_spans
    assert projector._pre_escape_rows(captured) is None


def test_capture_cannot_retain_an_earlier_pre_escape_eligibility():
    unit, keys = _fixture()
    projector, normalized = _projector(unit)
    definition = _definition(normalized, keys["capture"])
    old = projector._definition_atom(definition, definition.span, eligible=True)
    atom = old.atoms[0][0]
    assert atom in projector._eligible_atoms
    projector._blocked = frozenset({keys["capture"]})
    captured = projector._definition_atom(definition, definition.span, eligible=True)
    assert captured == old and atom in projector.ineligible_atoms
    assert atom not in projector._eligible_atoms


@pytest.mark.parametrize("option", ("fresh", "nonstack", "fresh-key"))
def test_capture_refuses_a_fresh_or_nonstack_claim(option):
    unit, keys = _fixture()
    projector, normalized = _projector(unit)
    projector._blocked = frozenset({keys["capture"]})
    definition = _definition(normalized, keys["capture"])
    options = {} if option == "fresh-key" else {option: True}
    if option == "fresh-key":
        projector._fresh = frozenset({keys["capture"]})
    projector._fresh_windows[keys["capture"]] = (32, "test-only-never-null")
    assert projector._definition_atom(definition, definition.span, **options) is None
    assert not projector._fresh_atoms and not projector._nonstack_atoms
    assert not projector._nonstack_extent and not projector._allocator_atoms


def test_partial_span_and_mismatched_output_cannot_be_captured():
    unit, keys = _fixture()
    projector, normalized = _projector(unit)
    projector._blocked = frozenset({keys["capture"]})
    definition = _definition(normalized, keys["capture"])
    partial = ByteSpan(definition.span.object_id, definition.span.start, 4)
    assert projector._definition_atom(definition, partial) is None
    # Even an exact requested span must match the observed LOAD output, not
    # merely a supplied definition record with the right operation key.
    for span in (partial, ByteSpan(definition.span.object_id, definition.span.start + 8, 8)):
        assert projector._definition_atom(replace(definition, span=span), span) is None


def test_repeated_load_has_no_once_only_capture_identity():
    unit, keys = _fixture(loop=True)
    projector, normalized = _projector(unit)
    projector._blocked = frozenset({keys["capture"]})
    definition = _definition(normalized, keys["capture"])
    assert keys["capture"] not in projector._once
    assert projector._definition_atom(definition, definition.span) is None
    rebuilt = _ScopedNormalizer()._normalize_once(unit, _blocked_reads=projector._blocked)
    assert isinstance(rebuilt, NormalizedFunction)
    assert any(rebuilt.memory_ssa.actions[row.action_id].operation_key == keys["store"]
               for row in rebuilt.memory_ssa.unresolved_writes)


def test_a_pending_writer_still_prevents_capturing_the_load_output():
    unit, keys = _fixture(debt="pending")
    projector, normalized = _projector(unit)
    projector._blocked = frozenset({keys["capture"]})
    projector._unsettled = _unsettled_reads(normalized.forward_inputs.effect_unit)
    assert projector._unsettled is not None and projector._unsettled(keys["capture"])
    definition = _definition(normalized, keys["capture"])
    assert projector._definition_atom(definition, definition.span) is None


def test_two_load_occurrences_do_not_share_identity_even_when_their_content_is_the_same():
    unit, keys = _fixture(second=True)
    projector, normalized = _projector(unit)
    assert projector._expression_from_memory_read(keys["capture"], 8) == \
        projector._expression_from_memory_read(keys["capture2"], 8)
    projector._blocked = frozenset({keys["capture"], keys["capture2"]})
    values = [projector._definition_atom(_definition(normalized, key), _definition(normalized, key).span)
              for key in (keys["capture"], keys["capture2"])]
    assert all(value is not None and value.atoms for value in values)
    assert values[0] != values[1]
    assert all(projector._expression_from_memory_read(key, 8) is None
               for key in (keys["capture"], keys["capture2"]))


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_rebuild_from_original_unit_connects_captured_pointer_store_read_not_old_constant(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    unit, keys = _fixture()
    rebuilt = _ScopedNormalizer()._normalize_once(unit, _blocked_reads=frozenset({keys["capture"]}))
    assert isinstance(rebuilt, NormalizedFunction)
    written = _definition(rebuilt, keys["store"])
    assert written.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
    assert written.span.start == 1 << 64 and written.span.size == 8
    assert written.span.object_id in rebuilt.wild_objects
    (read,) = _memory_reads(rebuilt, keys["read"])
    assert read.span == written.span and len(read.fragments) == 1
    identifier = rebuilt.memory_ssa.definitions.index(written)
    assert read.fragments[0].definition_ids == (identifier,)
    assert not any(row.span.object_id.kind is StorageObjectKind.ADDRESS_SPACE and row.span.start == OLD_ADDRESS
                   for row in (*rebuilt.memory_ssa.definitions, *rebuilt.memory_ssa.reads))
    graph, bindings = rebuilt.dependencies, rebuilt.memory_graph
    store_node, load_node = (graph.node_for_key("op:" + keys[name]) for name in ("store", "read"))
    definition_node = bindings.definition_nodes[identifier]
    assert any(target == definition_node and edge.kind == "memory_defines" and edge.span == written.span
               for _, target, edge in graph.out_edges(store_node))
    assert any(source == definition_node and edge.kind == "memory_read" and edge.span == written.span
               for source, _, edge in graph.in_edges(load_node))
    report = check(rebuilt, unit.observation, seeds=range(4),
                   register_pools=lambda seed: {RSP: 0x70000000, RDX: seed + 1})
    assert report.runs == 4 and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("debt", ("alias", "call"))
def test_capture_does_not_erase_real_alias_or_call_debt(debt):
    unit, keys = _fixture(debt=debt)
    rebuilt = _ScopedNormalizer()._normalize_once(unit, _blocked_reads=frozenset({keys["capture"]}))
    assert isinstance(rebuilt, NormalizedFunction)
    assert _definition(rebuilt, keys["store"]).span.object_id in rebuilt.wild_objects
    if debt == "alias":
        assert any(row.operation_key == keys["capture"] for row in rebuilt.may_alias_reads)
    else:
        assert any(row.operation_key == keys["read"] for row in rebuilt.call_clobber_reads)


def test_call_staging_and_memory_pointer_rows_are_not_raw_load_captures():
    builder = (FunctionBuilder().ins(store(const(SLOT), const(OLD_ADDRESS)))
               .call(0x1f00).ins(store(reg(RAX), reg(RDX))).ret())
    (unit,) = program_units(builder)
    plain = FunctionNormalizer().normalize(unit)
    registers = next(row.span.object_id for row in plain.memory_ssa.definitions
                     if row.span.object_id.kind is StorageObjectKind.REGISTER_FILE)
    global_ = next(row.span for row in plain.memory_ssa.definitions
                   if row.span.object_id.kind is StorageObjectKind.ADDRESS_SPACE and row.span.start == SLOT)
    access = AnchoredSpan(None, SLOT, 8, RAM, global_)
    run = ProvenRunEffect((ByteSpan(registers, RAX, 8),), (), (access,), value=("same_mem", access, False))
    call = next(f"1:{instruction.address.byte_offset:x}:{ordinal}:CALL"
                for instruction in unit.observation.instructions
                for ordinal, operation in enumerate(instruction.operations) if operation.opcode == "CALL")
    proven = ProvenCallEffect("1:1f00", (run,), (), preserves_memory=True, observes_registers=False)
    normalized = FunctionNormalizer().normalize(unit, proven_call_effects={call: proven})
    projector, _ = _projector(unit, normalized=normalized)
    result_key, reader_key = call + "~0", call + "~ld0"
    assert projector._pointer_rows[result_key][:3] == ("mem", reader_key, 8)
    staging = _definition(normalized, reader_key)
    before = projector._definition_atom(staging, staging.span)
    assert before is not None and before.byte_size == 1
    projector._blocked = frozenset({reader_key})
    assert projector._expression_from_memory_read(reader_key, 8) is None
    result = _definition(normalized, result_key)
    assert projector._pointer_row(result, result.span) is None
    assert projector._definition_atom(result, result.span) is None
    # This one-byte internal call-staging token is not an eight-byte memory
    # value or a raw LOAD output. Its pre-existing call atom is unchanged;
    # it neither rescues blocked content nor receives capture privileges.
    after = projector._definition_atom(staging, staging.span)
    assert after == before
    atom = after.atoms[0][0]
    assert atom not in projector.ineligible_atoms
    assert not projector.address_metadata["atoms"][atom].startswith("captured LOAD output")


def test_shared_content_identity_cannot_rescue_a_blocked_load():
    from test_shared_load_identity import _fixture as shared_fixture

    builder, keys = shared_fixture()
    (unit,) = program_units(builder)
    normalized = analyze_units([unit])["1:1000"].normalized
    assert normalized.load_value_proofs
    projector, _ = _projector(unit, normalized=normalized)
    projector._load_identities = {(proof.reader, proof.span.size): proof.value_class
                                  for proof in normalized.load_value_proofs}
    key = keys["first_index_load"]
    shared = projector._expression_from_memory_read(key, 4)
    assert shared is not None and shared.atoms
    projector._blocked = frozenset({key})
    assert projector._expression_from_memory_read(key, 4) is None
    definition = _definition(normalized, key)
    captured = projector._definition_atom(definition, definition.span)
    assert captured is not None and captured.atoms != shared.atoms


def test_real_shared_identity_planner_excludes_captured_output_candidates_after_rebuild():
    from test_forward_memory_refinement import _baseline
    from test_shared_load_identity import _fixture as shared_fixture
    from tdo_v2._load_identity import prepare_load_identities
    from tdo_v2.interprocedural import AnalyzedFunction
    from tdo_v2.relative_memory import IMAGE_BASE_TRACKING

    builder, keys = shared_fixture()
    original, options, memory_plan = _baseline(builder)
    assert memory_plan is not None
    memory_plan.bind(original.unit, options)
    readers = {keys["first_index_load"], keys["second_index_load"]}

    # A real N1 baseline is a positive control: with the genuine separation
    # plan the two original LOADs qualify for a shared STORE-content proof.
    normalizer = _ScopedNormalizer()
    before = normalizer._normalize_once(original.unit, **options, _forward_memory_plan=memory_plan)
    assert isinstance(before, NormalizedFunction)
    source = AnalyzedFunction("1:1000", original.unit, before, None)
    plan = prepare_load_identities(source, options)
    assert plan is not None and {proof.reader for proof in plan.proofs} == readers
    plan.verify()

    # Rebuild from the same original observation, blocking only content
    # substitution. Do not inject a cached identity or fabricate a graph.
    captured = normalizer._normalize_once(
        original.unit, **options, _forward_memory_plan=memory_plan, _blocked_reads=frozenset(readers))
    assert isinstance(captured, NormalizedFunction)
    assert captured.forward_inputs is not None and captured.may_alias_reads
    assert not captured.load_value_proofs and not captured.rep_blocks
    assert IMAGE_BASE_TRACKING.get() is None
    descriptions = dict(captured.address_atoms)
    marked = {description[len("captured LOAD output "):].split(" #", 1)[0]
              for description in descriptions.values() if description.startswith("captured LOAD output ")}
    assert readers <= marked
    assert not any(description.startswith("value of " + reader + " #")
                   for description in descriptions.values() for reader in readers)
    # Both byte-exact memory reads and their common original STORE are
    # still present; rejection is not a missing-candidate/early-return pass.
    for reader in readers:
        (read,) = _memory_reads(captured, reader)
        assert read.span.size == 4 and len(read.fragments) == 1
        (identifier,) = read.fragments[0].definition_ids
        definition = captured.memory_ssa.definitions[identifier]
        assert definition.kind is MemoryDefinitionKind.DATA_WRITE
        assert definition.operation_key == keys["index_store"] and definition.span == read.span
    result = AnalyzedFunction("1:1000", original.unit, captured, None)
    assert prepare_load_identities(result, options) is None
    plan.verify()  # the captured replay did not mutate the positive baseline
