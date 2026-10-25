"""Original DFB044: shared index LOAD values feed the existing last-writer SSA."""

from dataclasses import replace

import pytest

from test_forward_memory_footprints_binary import (
    ARRAY_LOAD, ARRAY_STORE, CONSTANT, INDEX_STORE, STRCPY, VARIABLE, _analyze, actual,
    test_original_pcode_bytes_values_addresses_and_widths as _raw_checks,
)
from tdo_v2._forward_memory import RefinementRefused
from tdo_v2.forward import Value, forward_facts
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_original_array_read_uses_the_original_store_definition_and_graph_edges(actual, monkeypatch, engine):
    old_roots, old = _analyze(actual, monkeypatch, True, engine)
    roots, results = _analyze(actual, monkeypatch, True, engine, identities=True)
    root = roots[VARIABLE]
    assert root.reached_origin_labels == ("dfb_source_A.ret", "dfb_source_C.ret")
    assert root.effective_completeness.reachable_unresolved_reads == 0
    assert root.is_locally_complete and root.is_effectively_complete
    assert old_roots[VARIABLE].effective_completeness.reachable_unresolved_reads == 1
    for key in (CONSTANT, STRCPY):
        assert roots[key] == old_roots[key]
    normalized = results[VARIABLE].normalized
    assert normalized.forward_memory_proofs == old[VARIABLE].normalized.forward_memory_proofs
    proofs = normalized.load_value_proofs
    assert {proof.reader for proof in proofs} == {"1b1:104c2d:1:LOAD", "1b1:104c39:1:LOAD"}
    assert len({proof.value_class for proof in proofs}) == 1
    assert all(proof.span.size == 4 and proof.definition[0] is MemoryDefinitionKind.DATA_WRITE
               and proof.definition[1] == INDEX_STORE for proof in proofs)
    ssa = normalized.memory_ssa
    (read,) = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == ARRAY_LOAD
               and row.span.object_id.kind.value in ("address_space", "function_relative")]
    assert read.span.size == 4 and len(read.fragments) == 1
    (fragment,) = read.fragments
    assert fragment.span == read.span and len(fragment.definition_ids) == 1
    (identifier,) = fragment.definition_ids
    definition = ssa.definitions[identifier]
    assert definition.kind is MemoryDefinitionKind.DATA_WRITE
    assert definition.operation_key == ARRAY_STORE and definition.span == read.span
    (store,) = [action for action in ssa.actions if action.operation_key == ARRAY_STORE]
    assert identifier in store.write_definition_ids
    assert store.write_definition_ids[definition.write_ordinal] == identifier
    graph = normalized.dependencies
    definition_node = normalized.memory_graph.definition_nodes[identifier]
    store_node, load_node = (graph.node_for_key("op:" + key) for key in (ARRAY_STORE, ARRAY_LOAD))
    assert any(source == store_node and target == definition_node and edge.kind == "memory_defines"
               and edge.occurrence == definition.write_ordinal and edge.span == read.span
               for source, target, edge in graph.out_edges(store_node))
    assert any(source == definition_node and target == load_node and edge.kind == "memory_read"
               and edge.span == read.span for source, target, edge in graph.in_edges(load_node))
    assert all(edge.kind != "may_alias_read" for _, _, edge in graph.in_edges(load_node))


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_original_eight_inputs_keep_all_raw_bytes_addresses_values_and_widths(actual, monkeypatch, engine):
    _raw_checks(actual, monkeypatch, engine, identities=True)


def test_full_replay_sparse_dense_and_forward_off(actual, monkeypatch):
    sparse_roots, sparse = _analyze(actual, monkeypatch, True, "sparse", identities=True)
    dense_roots, dense = _analyze(actual, monkeypatch, True, "dense", identities=True)
    assert sparse_roots == dense_roots
    for key in sparse:
        assert sparse[key].summary == dense[key].summary
        assert sparse[key].normalized.memory_ssa == dense[key].normalized.memory_ssa
        assert sparse[key].normalized.load_value_proofs == dense[key].normalized.load_value_proofs
    old_roots, old = _analyze(actual, monkeypatch, False, "sparse")
    off_roots, off = _analyze(actual, monkeypatch, False, "sparse", identities=True)
    assert off_roots == old_roots
    assert off_roots[VARIABLE].effective_completeness.reachable_unresolved_reads == 2
    for key in off:
        assert off[key].summary == old[key].summary
        assert off[key].normalized.memory_ssa == old[key].normalized.memory_ssa
        assert not off[key].normalized.load_value_proofs


@pytest.mark.parametrize("outcome", ("refused", "no-progress"))
def test_n2_failure_restores_the_complete_n1_result_and_publishes_only_n1_provenance(actual, monkeypatch, outcome):
    from tdo_v2._load_identity import LoadIdentityPlan

    roots_before, before = _analyze(actual, monkeypatch, True, "sparse")
    attempted = []
    normalize = FunctionNormalizer.normalize
    accepts = LoadIdentityPlan.accepts

    def refuse(self, unit, **options):
        if options.get("_load_identity_plan") is not None:
            attempted.append(unit)
            if outcome == "refused":
                raise RefinementRefused("actual N2 replay refusal")
        return normalize(self, unit, **options)

    def reject(self, result):
        return False if result.key == VARIABLE else accepts(self, result)

    monkeypatch.setattr(FunctionNormalizer, "normalize", refuse)
    if outcome == "no-progress":
        monkeypatch.setattr(LoadIdentityPlan, "accepts", reject)
    provenance = {}
    roots, results = _analyze(actual, monkeypatch, True, "sparse", identities=True, provenance=provenance)
    assert attempted
    assert roots == roots_before
    assert roots[VARIABLE].effective_completeness.reachable_unresolved_reads == 1
    assert set(provenance) == {id(result) for result in results.values()}
    for key, result in results.items():
        assert provenance[id(result)][0] is result
        assert result.summary == before[key].summary
        assert result.normalized.memory_ssa == before[key].normalized.memory_ssa
        assert result.normalized.forward_memory_proofs == before[key].normalized.forward_memory_proofs
        assert not result.normalized.load_value_proofs


@pytest.mark.parametrize("field", ("reader", "span", "definition", "value_class", "fact-id", "fact-claim",
                                    "fact-operation", "fact-context", "fact-requires", "requires"))
def test_original_load_identity_metadata_tampering_is_rejected_in_the_live_context(actual, monkeypatch, field):
    normalize = FunctionNormalizer.normalize
    attempted = []

    def inspect(self, unit, **options):
        plan = options.get("_load_identity_plan")
        if plan is not None:
            plan.verify()  # establish that the original plan is valid in this exact active policy context
            proof = plan.proofs[0]
            if field == "reader":
                altered = replace(proof, reader=ARRAY_LOAD)
            elif field == "span":
                altered = replace(proof, span=replace(proof.span, size=1))
            elif field == "definition":
                definition = list(proof.definition)
                definition[2] += 1
                altered = replace(proof, definition=tuple(definition))
            elif field == "value_class":
                altered = replace(proof, value_class=("def", "changed-store", "changed-span"))
            elif field == "requires":
                altered = proof
            else:
                fact = proof.address_fact
                changes = {"fact-id": {"id": "changed-id"}, "fact-claim": {"claim": Value.top(64)},
                           "fact-operation": {"operation": ARRAY_LOAD},
                           "fact-context": {"context": (VARIABLE, "1b1:104c25:2:CALL")},
                           "fact-requires": {"requires": ("forged-assumption",)}}
                altered = replace(proof, address_fact=replace(fact, **changes[field]))
            forged = replace(plan, proofs=(altered, *plan.proofs[1:]),
                             requires=("changed-requires",) if field == "requires" else plan.requires)
            selected = dict(plan.options)
            base = plan.baseline.forward_inputs.read_separations
            inputs = plan.baseline.forward_inputs
            for consume in (
                forged.verify,
                lambda: forged.bind(unit, selected, base),
                lambda: forged.bindings(inputs.effect_unit, inputs.observation, inputs.context, inputs.address_spaces,
                                        plan.baseline.memory_ssa),
                lambda: normalize(self, unit, **selected, _forward_memory_plan=base, _load_identity_plan=forged),
            ):
                with pytest.raises(RefinementRefused):
                    consume()
            attempted.append(unit)
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", inspect)
    _analyze(actual, monkeypatch, True, "sparse", identities=True)
    assert attempted


@pytest.mark.parametrize("foreign", ("effect-unit", "observation", "context", "spaces", "ssa-scope", "ssa-digest"))
def test_original_identity_consumer_rejects_foreign_activation_inputs(actual, monkeypatch, foreign):
    _, baseline = _analyze(actual, monkeypatch, True, "sparse")
    control = baseline[CONSTANT]
    normalize = FunctionNormalizer.normalize
    attempted = []

    def inspect(self, unit, **options):
        plan = options.get("_load_identity_plan")
        if plan is not None:
            inputs = plan.baseline.forward_inputs
            original = [inputs.effect_unit, inputs.observation, inputs.context,
                        inputs.address_spaces, plan.baseline.memory_ssa]
            # Reconstructed equivalent contexts are legitimate, unlike another function's context.
            equivalent = replace(inputs.context)
            assert equivalent is not inputs.context and equivalent == inputs.context
            assert plan.bindings(original[0], original[1], equivalent, original[3], original[4])
            changed = list(original)
            if foreign == "effect-unit":
                changed[0] = control.normalized.forward_inputs.effect_unit
            elif foreign == "observation":
                changed[1] = control.unit.observation
            elif foreign == "context":
                changed[2] = control.unit.scopes.resolution_context
            elif foreign == "spaces":
                changed[3] = tuple(replace(space, address_size_bits=32) if space.is_memory_space else space
                                   for space in inputs.address_spaces)
            elif foreign == "ssa-scope":
                changed[4] = control.normalized.memory_ssa
            else:
                changed[4] = replace(plan.baseline.memory_ssa, unit_digest=b"\xff" * 32)
            with pytest.raises(RefinementRefused):
                plan.bindings(*changed)
            attempted.append(unit)
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", inspect)
    roots, _ = _analyze(actual, monkeypatch, True, "sparse", identities=True)
    assert attempted and roots[VARIABLE].is_effectively_complete


@pytest.mark.parametrize("policy", ("image-base", "imports"))
def test_original_identity_consumer_rejects_changed_image_policies(actual, monkeypatch, policy):
    from tdo_v2.relative_memory import IMAGE_BASE_TRACKING, IMPORT_SLOTS, ImportSlots

    normalize = FunctionNormalizer.normalize
    attempted = []

    def inspect(self, unit, **options):
        plan = options.get("_load_identity_plan")
        if plan is not None:
            variable = IMAGE_BASE_TRACKING if policy == "image-base" else IMPORT_SLOTS
            value = object() if policy == "image-base" else ImportSlots(actual["image_info"])
            token = variable.set(value)
            try:
                with pytest.raises(RefinementRefused):
                    plan.bind(unit, dict(plan.options), plan.baseline.forward_inputs.read_separations)
                with pytest.raises(RefinementRefused):
                    plan.verify()
            finally:
                variable.reset(token)
            plan.verify()
            attempted.append(unit)
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", inspect)
    roots, _ = _analyze(actual, monkeypatch, True, "sparse", identities=True)
    assert attempted and roots[VARIABLE].is_effectively_complete


def test_original_model_and_n1_assumptions_survive_the_full_replay(actual, monkeypatch):
    _, before = _analyze(actual, monkeypatch, True, "sparse")
    _, after = _analyze(actual, monkeypatch, True, "sparse", identities=True)
    assert before[STRCPY].declared  # the original imported strcpy model makes this non-vacuous
    for key, original in before.items():
        assert original.declared == after[key].declared
        assert original.inherited_assumptions <= after[key].inherited_assumptions
    normalized = after[VARIABLE].normalized
    assert normalized.load_value_proofs
    assert set(before[VARIABLE].normalized.forward_memory_requires) <= set(normalized.forward_memory_requires)
    facts = forward_facts(normalized, after[VARIABLE].unit, readonly_image=actual["readonly"])
    assert facts
    labels = set(normalized.forward_memory_requires)
    for proof in normalized.load_value_proofs:
        labels.update(proof.address_fact.requires)
    assert all(labels <= set(fact.requires) for fact in facts)


@pytest.mark.parametrize("mode", ("settled", "blocked", "unsettled"))
def test_original_shared_values_keep_pending_blocked_and_stale_read_discipline(actual, monkeypatch, mode):
    from tdo_v2.relative_memory import _configured_projector, stale_reads

    normalize = FunctionNormalizer.normalize
    attempted = []

    def inspect(self, unit, **options):
        plan = options.get("_load_identity_plan")
        if plan is not None:
            inputs = plan.baseline.forward_inputs
            operations = {f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}": operation
                          for row in unit.observation.instructions for ordinal, operation in enumerate(row.operations)}
            language = unit.scopes.program.evidence.translation_namespace.language_id
            projector = _configured_projector(
                inputs.effect_unit, inputs.observation, inputs.context, inputs.address_spaces,
                plan.baseline.memory_ssa, operations, language, once_keys=frozenset(operations),
                load_identity_plan=plan)
            proof = plan.proofs[0]
            used = {}
            projector.used_reads = used
            if mode == "blocked":
                projector._blocked = frozenset({proof.reader})
            elif mode == "unsettled":
                projector._unsettled = lambda key: key == proof.reader
            value = projector._expression_from_memory_read(proof.reader, proof.span.size)
            if mode != "settled":
                assert value is None and not used
            else:
                assert value is not None and used == {(proof.reader, proof.span.size): {value}}
                valid = stale_reads(
                    inputs.effect_unit, inputs.observation, inputs.context, inputs.address_spaces,
                    plan.baseline.memory_ssa, used, translation_namespace=language,
                    once_keys=frozenset(operations), load_identity_plan=plan)
                assert not valid
                lost = stale_reads(
                    inputs.effect_unit, inputs.observation, inputs.context, inputs.address_spaces,
                    plan.baseline.memory_ssa, used, translation_namespace=language, once_keys=frozenset(operations))
                assert proof.reader in lost
            attempted.append(unit)
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", inspect)
    roots, _ = _analyze(actual, monkeypatch, True, "sparse", identities=True)
    assert attempted and roots[VARIABLE].is_effectively_complete
