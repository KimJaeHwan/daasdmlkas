"""DFB044 byte separations do not need entry-values-not-new-frame.

The original space selector is four bytes on STORE and eight on the two
epilogue LOADs. That encoding difference is not a different RAM space, nor a
different access width. Keep original p-code, SSA definitions and raw writers.
"""

from contextlib import contextmanager

import pytest

from forward_oracle import _Recording
from pcode_interpreter import Entry
from test_forward_memory_footprints_binary import (
    ARRAY_LOAD, ARRAY_STORE, CONSTANT, INDEX_LOAD, SOURCE_INPUTS, STRCPY, VARIABLE,
    _analyze, actual, test_original_pcode_bytes_values_addresses_and_widths as _raw_checks,
)
from tdo_v2 import _forward_memory, summary_engine
from tdo_v2._forward_memory import RefinementRefused
from tdo_v2.forward import forward_facts, probe
from tdo_v2.may_alias import ENTRY_VALUES_NOT_FRAME
from tdo_v2.memory_contracts import MemoryDefinitionKind


SAVED_RBP = "1b1:104bf6:2:STORE"
POP_RBP, RETURN_LOAD = "1b1:104c4a:1:LOAD", "1b1:104c4b:0:LOAD"
FRAME = "entry-values-do-not-address-the-new-frame"
HOME = "win64-home-space-callee-private"
EPILOGUE = (POP_RBP, RETURN_LOAD)


@contextmanager
def _public_policy(frame):
    """Set the public option, not only the ambient internal context variable."""
    public = summary_engine.analyze_observed_with_summaries
    runs = []

    def configured(*args, **options):
        options["assume_entry_values_not_frame"] = frame
        run = public(*args, **options)
        runs.append(run)
        return run

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(summary_engine, "analyze_observed_with_summaries", configured)
        yield patch, runs


def _frame_analysis(actual, frame, engine, *, forward=True):
    plans = []
    prepare = _forward_memory.prepare_memory_refinement

    def captured(result, options, **kwargs):
        plan = prepare(result, options, **kwargs)
        if result.key == VARIABLE and plan is not None:
            plans.append(plan)
        return plan

    with _public_policy(frame) as (patch, runs):
        patch.setattr(_forward_memory, "prepare_memory_refinement", captured)
        roots, results = _analyze(actual, patch, forward, engine, identities=True)
    assert len(runs) == 1
    return roots, results, runs[0], plans[-1] if plans else None


@pytest.fixture(scope="module", params=((True, "sparse"), (False, "sparse"),
                                      (True, "dense"), (False, "dense")),
                ids=("frame-on-sparse", "frame-off-sparse", "frame-on-dense", "frame-off-dense"))
def configured(actual, request):
    frame, engine = request.param
    return frame, engine, _frame_analysis(actual, frame, engine)


def _memory_read(normalized, key):
    ssa = normalized.memory_ssa
    (read,) = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == key
               and row.span.object_id.kind.value in ("address_space", "function_relative")]
    return read


def test_original_epilogue_separations_are_valid_with_either_frame_policy(actual, configured):
    frame, _, (roots, results, run, plan) = configured
    item = results[VARIABLE]
    normalized = item.normalized
    inputs = normalized.forward_inputs
    assert inputs.entry_values_not_frame is frame
    assert normalized.assumes_entry_values_not_frame is frame
    assert inputs.private_frame_above == 0  # original ELF/sysv64, no Win64 home policy
    assert roots[VARIABLE].reached_origin_labels == ("dfb_source_A.ret", "dfb_source_C.ret")
    assert roots[VARIABLE].effective_completeness.reachable_unresolved_reads == 0
    assert roots[VARIABLE].is_effectively_complete
    assert roots[CONSTANT].reached_origin_labels == ("dfb_source_B.ret",)
    assert roots[STRCPY].reached_origin_labels == ("dfb_source_A.ret",)

    # All three are plain original STORE/LOAD separations, not unknown or
    # uncertain writer exemptions. The two new proofs cover all eight bytes.
    proofs = {proof.read: proof for proof in normalized.forward_memory_proofs}
    assert set(proofs) == {INDEX_LOAD, *EPILOGUE}
    assert len(normalized.load_value_proofs) == 2
    assert plan is not None and len(plan.proofs) == 3
    for key in EPILOGUE:
        before = [row for row in plan.baseline.may_alias_reads if row.operation_key == key]
        assert len(before) == 1
        assert before[0].plain == (ARRAY_STORE,) and not before[0].uncertain
        assert not before[0].unknown_address
        proof = proofs[key]
        assert proof.writer == ARRAY_STORE and proof.span.size == 8
        assert not any(row.operation_key == key for row in normalized.may_alias_reads)
        assert proof.read_fact.claim.items[0][0] == proof.write_fact.claim.items[0][0] == ("entry", 0x20, 8)
        assert proof.write_fact.claim.items[0][1].lo == -40
        assert proof.write_fact.claim.items[0][1].hi == -28
        assert proof.write_fact.claim.items[0][1].stride == 4
    assert {row.operation_key for row in normalized.may_alias_reads} == {
        "1b1:104c44:2:CALL~ld0", "1b1:104c44:2:CALL~ld1"}
    assert all(row.plain == (ARRAY_STORE,) and not row.uncertain and not row.unknown_address
               for row in normalized.may_alias_reads)

    operations = {f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{n}:{op.opcode}": op
                  for instruction in item.unit.observation.instructions
                  for n, op in enumerate(instruction.operations)}
    selector = operations[ARRAY_STORE].inputs[0]
    assert selector.byte_size == 4 and operations[ARRAY_STORE].inputs[2].byte_size == 4
    for key in EPILOGUE:
        load = operations[key]
        assert load.inputs[0].kind == selector.kind
        assert load.inputs[0].coordinate == selector.coordinate
        assert load.inputs[0].byte_size == 8 and load.output.byte_size == 8
    (space,) = [space for space in inputs.address_spaces if space.space_id == selector.coordinate.byte_offset]
    assert space.is_memory_space and space.address_size_bits == 64

    # Separate current configuration from inherited model assumptions; never
    # scrub an inherited dependency just to advertise a switch as disabled.
    assert tuple(results[STRCPY].declared.values()) == ("external-model:crt-sysv64/strcpy@v7",)
    assert not results[STRCPY].inherited_assumptions
    inherited = {label for result in results.values() for label in result.inherited_assumptions}
    # Forward replay itself carries its dependencies in inherited_assumptions;
    # these must remain on ON, and must not be mistaken for model inheritance.
    assert (FRAME in inherited) is frame
    assert HOME not in inherited
    labels = summary_engine.run_assumptions(results, readonly_image=actual["readonly"])
    assert (FRAME in labels) is frame and (FRAME in run.assumptions) is frame
    assert HOME not in labels and HOME not in run.assumptions
    facts = forward_facts(normalized, item.unit, readonly_image=actual["readonly"], assumptions=labels)
    assert facts
    for required in [normalized.forward_memory_requires, *[fact.requires for fact in facts],
                     *[fact.requires for proof in proofs.values() for fact in (proof.read_fact, proof.write_fact)]]:
        assert (FRAME in required) is frame
        assert HOME not in required


def test_original_eight_byte_definitions_edges_and_probe_survive(configured):
    frame, _, (_, results, _, _) = configured
    normalized = results[VARIABLE].normalized
    ssa, graph = normalized.memory_ssa, normalized.dependencies
    for key in EPILOGUE:
        read = _memory_read(normalized, key)
        assert read.span.size == 8 and len(read.fragments) == 1
        (fragment,) = read.fragments
        assert fragment.span == read.span and len(fragment.definition_ids) == 1
        (identifier,) = fragment.definition_ids
        definition = ssa.definitions[identifier]
        if key == POP_RBP:
            assert definition.kind is MemoryDefinitionKind.DATA_WRITE
            assert definition.operation_key == SAVED_RBP and definition.span == read.span
            writer = graph.node_for_key("op:" + SAVED_RBP)
            assert any(source == writer and target == normalized.memory_graph.definition_nodes[identifier]
                       and edge.kind == "memory_defines" and edge.span == read.span
                       and edge.occurrence == definition.write_ordinal
                       for source, target, edge in graph.out_edges(writer))
        else:
            assert definition.kind is MemoryDefinitionKind.ENTRY and definition.operation_key is None
            assert definition.span.contains(read.span)
        definition_node = normalized.memory_graph.definition_nodes[identifier]
        reader = graph.node_for_key("op:" + key)
        assert any(source == definition_node and target == reader and edge.kind == "memory_read"
                   and edge.span == read.span for source, target, edge in graph.in_edges(reader))
        found, requires = probe(normalized, key, (read.span,))
        assert found == {read.span: identifier}
        assert (FRAME in requires) is frame
        assert HOME not in requires


def test_original_raw_eight_inputs_and_all_epilogue_writer_bytes(actual, configured):
    frame, engine, (_, results, _, _) = configured
    with _public_policy(frame) as (patch, _):
        _raw_checks(actual, patch, engine, identities=True)
    item = results[VARIABLE]
    for number, seed in enumerate(SOURCE_INPUTS):
        stack = 0x70000000 + 0x100 * number
        vm = _Recording(item.unit.observation, subjects={key: 1 for key in EPILOGUE},
                        constant_space=actual["constant"], seed=number,
                        program=actual["program"], image=actual["image"], address_bits=actual["address_bits"])
        vm.preset(actual["register"], 0x20, 8, stack)
        global_ = actual["source_global"]
        vm.preset(global_.space_id, global_.byte_offset, 4, seed)
        run = vm.run()
        assert run.completed and run.executed and not vm.opaque_opcodes
        for key, address in ((POP_RBP, stack - 8), (RETURN_LOAD, stack)):
            assert vm.seen[key] == [address]
            expected = {address + byte: SAVED_RBP if key == POP_RBP else Entry(0x1B1, address + byte)
                        for byte in range(8)}
            assert {row.offset: row.writer for row in run.dependencies
                    if row.reader == key and row.space_id == 0x1B1} == expected
            assert {address + byte: vm._bytes[(0x1B1, address + byte)][1] for byte in range(8)} == expected


@pytest.mark.parametrize("frame", (True, False))
@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_forward_off_keeps_the_original_unrefined_analysis(actual, frame, engine):
    roots, results, _, plan = _frame_analysis(actual, frame, engine, forward=False)
    normalized = results[VARIABLE].normalized
    assert plan is None
    assert not normalized.forward_memory_proofs and not normalized.load_value_proofs
    assert normalized.forward_inputs is None
    assert roots[VARIABLE].reached_origin_labels == ("dfb_source_A.ret", "dfb_source_C.ret")
    assert roots[VARIABLE].effective_completeness.reachable_unresolved_reads == 2
    assert not roots[VARIABLE].is_effectively_complete
    for key in EPILOGUE:
        assert any(row.operation_key == key and row.plain == (ARRAY_STORE,)
                   for row in normalized.may_alias_reads)


def test_original_plan_rejects_the_other_frame_policy(configured):
    frame, _, (_, _, _, plan) = configured
    assert plan is not None
    token = ENTRY_VALUES_NOT_FRAME.set(frame)
    try:
        plan.verify()
        opposite = ENTRY_VALUES_NOT_FRAME.set(not frame)
        try:
            with pytest.raises(RefinementRefused):
                plan.verify()
            with pytest.raises(RefinementRefused):
                plan.bind(plan.unit, dict(plan.options))
        finally:
            ENTRY_VALUES_NOT_FRAME.reset(opposite)
    finally:
        ENTRY_VALUES_NOT_FRAME.reset(token)
