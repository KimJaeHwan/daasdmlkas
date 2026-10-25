"""Original TraceGrow activation keeps evidenced ranges, not all memory.

Uses the pinned Trace fixture and existing model assumptions. This is not a
strict raw allocator theorem, an extent proof, or proof that UAF is absent.
Negative controls below withdraw captured input/model evidence only; they do
not modify or replace the admitted UE instructions or the shipped models.
"""

from dataclasses import replace

import pytest

from test_callee_preserved_low_binary import R002, _projector, trace
from test_entry_frame_ue_limits_binary import FRAME, HOME, _trace_analysis
from tdo_v2 import _call_activation
from tdo_v2._call_memory import refine_call_memory
from tdo_v2.constant_value import ExactConstant
from tdo_v2.forward import _analyze, probe
from tdo_v2.may_alias import ENTRY_VALUES_NOT_FRAME
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.query import BackwardSliceQuery


GROW = "1b1:180005af0"
FIRST, SECOND = "1b1:180006053:2:CALL", "1b1:1800061ea:2:CALL"
ZERO, OLD_LOAD = "1b1:180005eee:1:STORE", "1b1:180005b84:0:LOAD"
REALLOC, STORE, LOAD = "1b1:180005b87:3:CALLIND", "1b1:180005b56:2:STORE", "1b1:180005b8d:1:LOAD"
BIAS = 1 << 64


@pytest.fixture(autouse=True)
def forward_on(monkeypatch, activation_case):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", activation_case["engine"])
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", activation_case["engine"])


@pytest.fixture(scope="module", params=((False, "sparse"), (True, "sparse"),
                                      (False, "dense"), (True, "dense")),
                ids=("frame-off-sparse", "frame-on-sparse", "frame-off-dense", "frame-on-dense"))
def activation_case(trace, request):
    frame, engine = request.param
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "1")
        patch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
        patch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
        result = _trace_analysis(trace, frame, trace["models"])
        current = result["trace"][R002]
        adopted = current.activations.get(FIRST)
        if adopted is None:
            caller, callee = current, result["trace"][GROW]
        else:
            # Automatic integration retains the exact original N0 owner.
            caller, callee, call, *_ = adopted.activation_witness
            assert call == FIRST
        options = dict(readonly_image=trace["image"], assumptions=result["engine_run"].assumptions)
        replay = _call_activation.replay_activation(caller, callee, FIRST, **options)
        assert replay is not None
        replay = refine_call_memory(replay, **options)
    assert replay is not None
    provenance = result["provenance"]
    generic_owner, generic_note = provenance[id(callee)]
    assert generic_owner is callee
    note_snapshot = {name: dict(getattr(generic_note, name))
                     for name in ("sources", "rejections", "failed", "opened", "final", "sink")}
    return dict(frame=frame, engine=engine, caller=caller, callee=callee, replay=replay, options=options,
                current=current, adopted=adopted, provenance=provenance, generic_note_snapshot=note_snapshot)


def _read(item, key):
    ssa = item.normalized.memory_ssa
    (read,) = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == key
               and row.span.object_id.kind.value == "function_relative"]
    return read


def test_public_replay_uses_original_caller_zero_and_full_width_null_input(activation_case):
    case = activation_case
    caller, callee, replay = (case[key] for key in ("caller", "callee", "replay"))
    owner, original, call, witnesses = replay.activation_witness
    assert owner is caller and original is callee and call == FIRST
    state = replay.normalized.activation_entry
    assert state.context == (R002, FIRST)
    assert [(destination.start, destination.size, base.start, base.size, delta)
            for destination, base, delta in state.registers] == [(8, 8, 32, 8, 80)]
    (seed,) = [(span, literal) for span, literal in state.memory
               if span.start == BIAS + 80 and span.size == 8]
    assert seed[1] == ExactConstant(8, 0)
    (witness,) = [row for row in witnesses if row[1][1] == ZERO]
    source, identity, literal = witness
    assert source.size == 8 and literal == ExactConstant(8, 0)
    assert identity[0] is MemoryDefinitionKind.DATA_WRITE and identity[1] == ZERO
    assert any(definition.operation_key == ZERO and definition.span == source
               for definition in caller.normalized.memory_ssa.definitions)
    caller_projector, caller_ops = _projector(caller)
    assert caller_ops[ZERO].inputs[2].byte_size == 8
    zero = caller_projector._expression_for_input(ZERO, caller_ops[ZERO].inputs[2])
    assert zero is not None and zero.byte_size == 8 and zero.image == 0
    assert not zero.atoms and zero.displacement == 0

    _, operations = _projector(replay)
    assert operations[OLD_LOAD].opcode == "LOAD"
    assert operations[OLD_LOAD].output.byte_size == 8
    moved = operations["1b1:180005b84:1:COPY"]
    assert moved.inputs == (operations[OLD_LOAD].output,)
    assert moved.output.coordinate.byte_offset == 8 and moved.output.byte_size == 8
    effect = replay.proven[REALLOC]
    (argument,) = [source for _, source in effect.same_object_registers]
    assert argument.start == 8 and argument.size == 8
    analysis = _analyze(replay.normalized, replay.unit, **case["options"])
    values, used = analysis.bind(REALLOC, (argument,))
    assert values[argument].single_number() == 0
    assert set(used) <= set(state.requires)
    (claim,) = [row for row in replay.call_memory_decisions
                if row.preserved and (row.demand.call, row.demand.reader) == (REALLOC, LOAD)]
    assert claim.demand.span.start == BIAS - 24 and claim.demand.span.size == 8
    assert "external-model:ue-core-win64/FMemory::Realloc@" in claim.model_label


def test_demanded_s8_call_debt_is_removed_with_original_ssa_and_graph_writers(activation_case):
    case = activation_case
    generic, replay = case["callee"], case["replay"]
    before, after = generic.proven[REALLOC], replay.proven[REALLOC]
    read = _read(replay, LOAD)
    assert read.span.start == BIAS - 24 and read.span.size == 8
    assert not before.preserves_memory and not after.preserves_memory
    assert read.span in set(after.preserved) - set(before.preserved)
    assert set(after.preserved) - set(before.preserved) == {
        row.demand.span for row in replay.call_memory_decisions if row.preserved and row.demand.call == REALLOC}
    assert set(before.preserved) <= set(after.preserved)
    assert replace(after, preserved=before.preserved) == before
    assert all(replay.proven[key] == effect for key, effect in generic.proven.items() if key != REALLOC)
    assert len(read.fragments) == 1 and read.fragments[0].span == read.span
    (identifier,) = read.fragments[0].definition_ids
    ssa, graph = replay.normalized.memory_ssa, replay.normalized.dependencies
    definition = ssa.definitions[identifier]
    assert definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.operation_key == STORE
    assert definition.span == read.span
    found, requires = probe(replay.normalized, LOAD, (read.span,))
    assert found == {read.span: identifier}
    assert set(requires) <= set(replay.normalized.activation_entry.requires)
    writer_node, reader_node = (graph.node_for_key("op:" + key) for key in (STORE, LOAD))
    definition_node = replay.normalized.memory_graph.definition_nodes[identifier]
    assert any(source == writer_node and target == definition_node and edge.kind == "memory_defines"
               and edge.span == read.span for source, target, edge in graph.out_edges(writer_node))
    assert any(source == definition_node and target == reader_node and edge.kind == "memory_read"
               and edge.span == read.span for source, target, edge in graph.in_edges(reader_node))
    assert writer_node in BackwardSliceQuery().run(replay.normalized, reader_node).reachable_nodes
    assert not any(row.operation_key == LOAD and REALLOC in row.intervening_calls
                   and any(span.overlaps(read.span) for span in row.spans)
                   for row in replay.normalized.call_clobber_reads)
    assert any(row.operation_key == LOAD and REALLOC in row.intervening_calls
               for row in generic.normalized.call_clobber_reads)
    assert probe(generic.normalized, LOAD, (_read(generic, LOAD).span,))[0][_read(generic, LOAD).span] is None


def test_generic_and_second_call_remain_unknown_and_no_assumptions_are_invented(activation_case):
    case = activation_case
    caller, callee = case["caller"], case["callee"]
    before = (callee.normalized, callee.summary, dict(callee.proven))
    second = _call_activation.replay_activation(caller, callee, SECOND, **case["options"])
    assert second is not None and second.normalized.activation_entry.context == (R002, SECOND)
    second = refine_call_memory(second, **case["options"])
    assert not any(row.preserved and row.demand.call == REALLOC for row in second.call_memory_decisions)
    assert second.proven[REALLOC] == callee.proven[REALLOC]
    assert any(row.operation_key == LOAD and REALLOC in row.intervening_calls
               for row in second.normalized.call_clobber_reads)
    assert before == (callee.normalized, callee.summary, callee.proven)
    requires = set(case["replay"].normalized.activation_entry.requires)
    assert requires == set(case["options"]["assumptions"])
    assert (FRAME in requires) is case["frame"]
    assert (HOME in requires) is case["frame"]
    assert case["replay"].inherited_assumptions == callee.inherited_assumptions | frozenset(requires)


def test_public_replay_restores_captured_off_policy_despite_ambient_on(activation_case):
    case = activation_case
    token = ENTRY_VALUES_NOT_FRAME.set(True)
    try:
        replay = _call_activation.replay_activation(case["caller"], case["callee"], FIRST, **case["options"])
        replay = refine_call_memory(replay, **case["options"])
        assert ENTRY_VALUES_NOT_FRAME.get() is True
    finally:
        ENTRY_VALUES_NOT_FRAME.reset(token)
    assert replay is not None
    assert replay.normalized.forward_inputs.entry_values_not_frame is case["frame"]
    assert replay.normalized.activation_entry == case["replay"].normalized.activation_entry
    assert replay.summary == case["replay"].summary


@pytest.mark.parametrize("control", ("nonzero", "partial", "missing"))
def test_withdrawn_input_seed_control_cannot_authorize_the_actual_s8(activation_case, monkeypatch, control):
    # Deliberate captured-input negative controls, not alternative admitted
    # caller instructions or evidence that the real caller stores nonzero.
    memory_inputs = _call_activation._memory_inputs
    intercepted = []

    def withdrawn(*args, **kwargs):
        seeds, witnesses, labels = memory_inputs(*args, **kwargs)
        changed = []
        for span, literal in seeds:
            if span.start == BIAS + 80 and span.size == 8:
                intercepted.append((span, literal))
                if control == "nonzero":
                    changed.append((span, ExactConstant(8, 1)))
                elif control == "partial":
                    changed.append((replace(span, size=4), ExactConstant(4, 0)))
            else:
                changed.append((span, literal))
        return tuple(changed), witnesses, labels

    monkeypatch.setattr(_call_activation, "_memory_inputs", withdrawn)
    case = activation_case
    replay = _call_activation.replay_activation(case["caller"], case["callee"], FIRST, **case["options"])
    assert replay is not None
    replay = refine_call_memory(replay, **case["options"])
    assert not any(row.preserved and row.demand.call == REALLOC for row in replay.call_memory_decisions)
    assert replay.proven[REALLOC] == case["callee"].proven[REALLOC]
    assert any(row.operation_key == LOAD and REALLOC in row.intervening_calls
               for row in replay.normalized.call_clobber_reads)
    assert intercepted and all(literal == ExactConstant(8, 0) for _, literal in intercepted)


def test_caller_without_captured_forward_evidence_is_not_a_seed(activation_case):
    case = activation_case
    missing = replace(case["caller"], normalized=replace(case["caller"].normalized, forward_inputs=None))
    assert _call_activation.replay_activation(missing, case["callee"], FIRST, **case["options"]) is None


@pytest.mark.parametrize("control", ("other-memory-not-kept", "callback-refused", "callback-invokes"))
def test_withdrawn_matched_model_contract_keeps_context_but_refuses_preservation(activation_case, control):
    # Deliberate metadata boundary controls. No shipped model file or raw
    # callee is changed, and the original model's labels are not stripped.
    case = activation_case
    changed = []
    for call, model, entry in case["callee"].lifetime_models:
        options = ({"keeps_other_memory": False} if control == "other-memory-not-kept" else
                   {"refusal": "callback contract withdrawn"} if control == "callback-refused" else
                   {"callbacks_invokes": ((0, 8),)})
        altered = replace(entry, **options)
        assert altered.label == entry.label
        changed.append((call, model, altered))
    assert changed
    refused = replace(case["callee"], lifetime_models=tuple(changed))
    replay = _call_activation.replay_activation(case["caller"], refused, FIRST, **case["options"])
    assert replay is not None
    replay = refine_call_memory(replay, **case["options"])
    assert not any(row.preserved for row in replay.call_memory_decisions)
    assert replay.proven[REALLOC] == case["callee"].proven[REALLOC]


def test_public_replay_is_refused_with_runtime_forward_off(activation_case, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    case = activation_case
    assert _call_activation.replay_activation(case["caller"], case["callee"], FIRST, **case["options"]) is None


def test_adopted_call_provenance_keeps_only_exact_context_effect_notes(activation_case):
    case = activation_case
    current, generic, context = case["current"], case["callee"], case["adopted"]
    assert context is not None and context is current.activations[FIRST]
    assert context is not generic and context.key == generic.key == GROW
    provenance = case["provenance"]
    caller_owner, caller_note = provenance[id(current)]
    generic_owner, generic_note = provenance[id(generic)]
    context_owner, context_note = provenance[id(context)]
    assert caller_owner is current and generic_owner is generic and context_owner is context
    first_kind, first_source = caller_note.sources[FIRST]
    second_kind, second_source = caller_note.sources[SECOND]
    assert first_kind == second_kind == "summary"
    assert first_source is context
    assert second_source is current.activations.get(SECOND, generic)
    if SECOND in current.activations:
        second = current.activations[SECOND]
        assert second.normalized.activation_entry.context == (R002, SECOND)
        assert not any(row.preserved and row.demand.call == REALLOC for row in second.call_memory_decisions)
    # A specialized CALL has a new effect/condition domain. Its former cr/ck
    # ordinals and model source are not an activation-local verdict. Only
    # exactly unchanged effects may carry a copied generic note.
    assert context_note is not generic_note
    unchanged = {call for call, effect in generic.proven.items()
                 if call in context.proven and context.proven[call] == effect}
    assert REALLOC not in unchanged
    for name, snapshot in case["generic_note_snapshot"].items():
        assert getattr(generic_note, name) == snapshot
        copied = getattr(context_note, name)
        assert copied is not getattr(generic_note, name)
        assert copied == {key: value for key, value in snapshot.items()
                          if (key[0] if name in ("final", "sink") else key) in unchanged}
    assert context_note.memory_sources is not generic_note.memory_sources
    assert context_note.memory_sources == {call: rows for call, rows in generic_note.memory_sources.items()
                                           if call in unchanged}
    for call in unchanged:
        if call in context_note.opened:
            assert context_note.opened[call] is not generic_note.opened[call]
        if call in context_note.memory_sources:
            assert context_note.memory_sources[call] is not generic_note.memory_sources[call]
    assert REALLOC not in context_note.sources
    assert REALLOC not in context_note.failed and REALLOC not in context_note.opened
    assert not any(call == REALLOC for call, _ in context_note.final)
    assert not any(call == REALLOC for call, _ in context_note.sink)
    from tdo_v2.operation_records import _call_provenance

    assert _call_provenance(context_note, REALLOC, context.proven[REALLOC], "0")["source"] is None
    assert generic_note.sources[REALLOC] == ("model", generic.proven[REALLOC].callee)
    assert context.declared == generic.declared
    assert context.lifetime_models == generic.lifetime_models
    assert context.summary.writer_conditions == generic.summary.writer_conditions
    assert context.activation_witness[0] is case["caller"]
    assert context.activation_witness[1] is generic and context.activation_witness[2] == FIRST
    (claim,) = [row for row in context.call_memory_decisions
                if row.preserved and (row.demand.call, row.demand.reader) == (REALLOC, LOAD)]
    span = claim.demand.span
    assert span.start == BIAS - 24 and span.size == 8
    old, new = generic.proven[REALLOC], context.proven[REALLOC]
    assert span in set(new.preserved) - set(old.preserved)
    assert replace(new, preserved=old.preserved) == old
    assert not old.preserves_memory and not new.preserves_memory
    assert all(context.proven[key] == effect for key, effect in generic.proven.items() if key != REALLOC)


def test_adopted_caller_revalidates_only_the_original_fresh_owner_snapshot(activation_case, monkeypatch):
    case = activation_case
    original, candidate, context = case["caller"], case["current"], case["adopted"]
    assert context is not None
    assert _call_activation.revalidate_activation(original, candidate, context, **case["options"])
    # An equivalent-looking object is not the owner captured by this proof;
    # a different function is not an adopted instance of the same caller.
    assert not _call_activation.revalidate_activation(replace(original), candidate, context, **case["options"])
    assert not _call_activation.revalidate_activation(original, case["callee"], context, **case["options"])
    missing = replace(candidate, normalized=replace(candidate.normalized, forward_inputs=None))
    assert not _call_activation.revalidate_activation(original, missing, context, **case["options"])
    # Deliberate stale-snapshot negative control. No admitted instruction is
    # changed, and the exact original owner is restored after this check.
    with monkeypatch.context() as patch:
        patch.setattr(original, "normalized", replace(original.normalized))
        assert not _call_activation.revalidate_activation(original, candidate, context, **case["options"])
    assert _call_activation.revalidate_activation(original, candidate, context, **case["options"])
