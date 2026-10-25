"""Preserve equal, settled STORE values across distinct original LOADs.

The existing projector consumes value-class atoms; the existing SSA and alias
analysis, not this module, decide the last writer of subsequent array reads.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ._forward_memory import RefinementRefused, _offsets, _signature
from .memory_contracts import MemoryDefinitionKind
from .resource_limits import step
from .span_geometry import StorageObjectKind

MAX_LOAD_IDENTITIES = 64


def _policy_signature(options):
    from .relative_memory import IMAGE_BASE_TRACKING, IMPORT_SLOTS

    return _signature(options), id(IMPORT_SLOTS.get()), id(IMAGE_BASE_TRACKING.get())


def definition_identity(row):
    return (row.kind, row.operation_key, row.write_ordinal, row.block_key, row.span)


@dataclass(frozen=True, slots=True)
class LoadIdentity:
    reader: str
    span: object
    definition: tuple
    value_class: tuple
    address_fact: object


@dataclass(frozen=True, slots=True)
class LoadIdentityPlan:
    source: object
    unit: object
    baseline: object
    options: tuple
    signature: tuple
    proofs: tuple[LoadIdentity, ...]
    requires: tuple[str, ...]

    def verify(self):
        if self.source.unit is not self.unit or self.source.normalized is not self.baseline:
            raise RefinementRefused("load identity baseline changed")
        expected = prepare_load_identities(self.source, dict(self.options))
        if expected is None or expected.signature != self.signature or expected.proofs != self.proofs \
                or expected.requires != self.requires:
            raise RefinementRefused("original LOAD/STORE value identity changed")

    def bind(self, unit, options, base_plan):
        if unit is not self.unit or _policy_signature(options) != self.signature \
                or base_plan is not self.baseline.forward_inputs.read_separations:
            raise RefinementRefused("load identity replay inputs changed")
        self.verify()

    def bindings(self, effect_unit, observation, context, address_spaces, ssa):
        from .effect_decode import decode_effect_unit

        self.verify()
        original = self.baseline.forward_inputs
        if effect_unit.function_scope != self.unit.scopes.function.scope or observation is not self.unit.observation \
                or context != original.context or address_spaces != original.address_spaces \
                or ssa.function_scope != effect_unit.function_scope \
                or ssa.unit_digest != decode_effect_unit(effect_unit).canonical_digest:
            raise RefinementRefused("shared LOAD consumer changed activation or storage context")
        return {(proof.reader, proof.span.size): proof.value_class for proof in self.proofs}

    def accepts(self, result):
        """Recheck original byte writers, then require real SSA last-write progress."""
        from .forward import probe
        from .normalize import NormalizedFunction

        if result.unit is not self.unit or type(result.normalized) is not NormalizedFunction:
            return False
        normalized = result.normalized
        for proof in self.proofs:
            step()
            found, _ = probe(normalized, proof.reader, (proof.span,))
            identifier = found.get(proof.span)
            if type(identifier) is not int or definition_identity(normalized.memory_ssa.definitions[identifier]) \
                    != proof.definition:
                return False
        before = {row.operation_key for row in self.baseline.may_alias_reads}
        after = {row.operation_key for row in (*normalized.may_alias_reads, *normalized.call_clobber_reads)}
        ssa = normalized.memory_ssa
        for read in ssa.reads:
            step()
            key = ssa.actions[read.action_id].operation_key
            if key not in before or key in after or not key.endswith(":LOAD") \
                    or read.span.object_id.kind not in (StorageObjectKind.FUNCTION_RELATIVE,
                                                       StorageObjectKind.ADDRESS_SPACE) \
                    or len(read.fragments) != 1:
                continue
            fragment = read.fragments[0]
            if fragment.span != read.span or len(fragment.definition_ids) != 1:
                continue
            definition = ssa.definitions[fragment.definition_ids[0]]
            if definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.span == read.span \
                    and definition.operation_key is not None and definition.operation_key.endswith(":STORE"):
                found, _ = probe(normalized, key, (read.span,))
                if found.get(read.span) == fragment.definition_ids[0]:
                    return True
        return False


def prepare_load_identities(result, options):
    from .forward import forward_facts, probe
    from ._scope_contracts import VarnodeKindCode
    from .normalize import NormalizedFunction
    from .pcode_blocks import build_pcode_block_graph
    from .relative_memory import IMAGE_BASE_TRACKING, _configured_projector, single_execution_keys
    from .summary_engine import run_assumptions

    normalized, unit = result.normalized, result.unit
    if type(normalized) is not NormalizedFunction or normalized.forward_inputs is None \
            or normalized.load_value_proofs or normalized.rep_blocks or not normalized.may_alias_reads \
            or IMAGE_BASE_TRACKING.get() is not None:
        return None
    operations = {}
    for row in unit.observation.instructions:
        for ordinal, operation in enumerate(row.operations):
            step()
            operations[f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}"] = operation
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    once = single_execution_keys(unit.observation, graph)
    inputs = normalized.forward_inputs
    projector = _configured_projector(
        inputs.effect_unit, unit.observation, inputs.context, inputs.address_spaces, normalized.memory_ssa,
        operations, unit.scopes.program.evidence.translation_namespace.language_id, once_keys=once)
    labels = set(run_assumptions({result.key: result}, readonly_image=options.get("readonly_image"),
                                home_space=options.get("private_frame_above", 0)))
    labels.update(normalized.forward_memory_requires)
    facts = {fact.operation: fact for fact in forward_facts(normalized, unit,
             readonly_image=options.get("readonly_image"), assumptions=tuple(sorted(labels)))}
    # Only LOAD atoms that already participate in the original address graph.
    atom_readers = set()
    for _, description in normalized.address_atoms:
        step()
        if description.startswith("value of "):
            key = description[len("value of "):].split(" #", 1)[0]
            if key in operations and operations[key].opcode == "LOAD":
                atom_readers.add(key)
    groups = defaultdict(list)
    ssa = normalized.memory_ssa
    for read in ssa.reads:
        step()
        key = ssa.actions[read.action_id].operation_key
        operation, fact = operations.get(key), facts.get(key)
        if key not in once or key not in atom_readers or operation is None or fact is None \
                or operation.output is None or read.span.size != operation.output.byte_size \
                or read.span.object_id.kind not in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE) \
                or len(read.fragments) != 1:
            continue
        offsets = _offsets(fact, read.span.size)
        space = next((row for row in inputs.address_spaces
                      if row.space_id == operation.inputs[0].coordinate.byte_offset), None)
        if offsets is None or len(offsets[1]) != read.span.size or space is None \
                or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT or not space.is_memory_space \
                or space.address_size_bits != 64 or operation.inputs[1].byte_size != 8:
            continue
        fragment = read.fragments[0]
        if fragment.span != read.span or len(fragment.definition_ids) != 1:
            continue
        identifier = fragment.definition_ids[0]
        definition = ssa.definitions[identifier]
        writer = operations.get(definition.operation_key)
        if definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.span != read.span \
                or definition.operation_key not in once or writer is None or writer.opcode != "STORE" \
                or writer.inputs[0] != operation.inputs[0] or writer.inputs[1].byte_size != 8 \
                or writer.inputs[2].byte_size != read.span.size:
            continue
        found, requires = probe(normalized, key, (read.span,))
        if found.get(read.span) != identifier:
            continue
        value_class = projector._slot_class(key, read.span.size, None)
        if value_class is None or value_class[0] != "def":
            continue
        labels.update(requires)
        labels.update(fact.requires)
        groups[value_class].append(LoadIdentity(key, read.span, definition_identity(definition), value_class, fact))
    proofs = tuple(sorted((proof for group in groups.values() if len({item.reader for item in group}) > 1
                           for proof in group), key=lambda item: item.reader))
    if not proofs or len(proofs) > MAX_LOAD_IDENTITIES:
        return None
    return LoadIdentityPlan(result, unit, normalized, tuple(options.items()), _policy_signature(options), proofs,
                            tuple(sorted(labels)))
