"""Context transport and CALL range proofs are independent SSA consumers."""
from dataclasses import replace
import pytest

from synthetic import (RAX, RBX, RCX, RDX, RDI, RSP, FunctionBuilder, add, const,
                       copy, load, op, program_units, ram, reg, store, tmp)
from test_call_activation_lifetime import _key, _read, _run, models
from test_external_models import THUNKS, _image
from tdo_v2 import _call_activation
from tdo_v2._call_memory import refine_call_memory
from tdo_v2._forward_memory import RefinementRefused, _freeze
from tdo_v2.forward import _analyze, probe
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.may_alias import ENTRY_VALUES_NOT_FRAME
from tdo_v2.normalize import NormalizationFailureReason, UnresolvedNormalizedFunction
from tdo_v2.query import BackwardSliceQuery
from tools.graph_fidelity.semantic_snapshot import encode


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def mode(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)


def _analyze_units(*builders, models=None):
    return analyze_units(program_units(*builders), image_info=_image(), external_models=models,
                         private_frame_above=40, assume_globals_disjoint_from_stack=True,
                         assume_entry_values_not_frame=False,
                         assume_opaque_callees_leave_no_stack_addresses=False)


@pytest.mark.parametrize("constant", (None, 0, 29))
def test_entry_transport_does_not_need_lifetime_models_or_preservation(constant):
    caller = FunctionBuilder().sub_rsp(0x80).ins(add(reg(RCX), reg(RSP), const(0x30)))
    if constant is not None:
        caller.ins(store(reg(RCX), const(constant)))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x80).ret()
    callee = FunctionBuilder(0x1600)
    reader = _key(callee, 0, "LOAD")
    callee.ins(load(reg(RAX), reg(RCX))).ret()
    result = _analyze_units(caller, callee)
    owner, generic = result["1:1000"], result["1:1600"]
    original = owner.activations[outer].activation_witness[0] if outer in owner.activations else owner
    context = _call_activation.replay_activation(original, generic, outer)
    assert context is not None and not generic.lifetime_models
    assert context.proven == generic.proven and not context.call_memory_decisions
    assert bool(context.normalized.activation_entry.memory) is (constant is not None)
    assert context.normalized.activation_entry.registers
    assert context.normalized.activation_entry.context == (owner.key, outer)
    refined = refine_call_memory(context)
    assert not any(row.preserved for row in refined.call_memory_decisions)
    assert refined.normalized is context.normalized and refined.summary == context.summary
    if constant is not None:
        read = _read(context, reader)
        values, _ = _analyze(context.normalized, context.unit).bind(reader, (read.span,))
        assert values[read.span].single_number() == constant
    assert generic.normalized.activation_entry is None


def _range_case(models, *, width=8, after="delay", multiple=False, old_pointer=0):
    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(add(reg(RCX), reg(RSP), const(0x30)), store(reg(RCX), const(old_pointer))))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x80).ret()
    callee = FunctionBuilder(0x1600).sub_rsp(0x48).ins(copy(reg(RBX), reg(RCX)))
    saved = _key(callee, 1, "STORE")
    callee.ins(add(tmp(0x100), reg(RSP), const(0x30)), store(tmp(0x100), reg(RBX)))
    callee.ins(load(reg(RCX), reg(RBX))).ins(copy(reg(RDX), const(16)))
    realloc = _key(callee, 2, "CALL")
    callee.call(THUNKS["realloc"])
    later = None
    if after == "unknown-call":
        later = _key(callee, 2, "CALL")
        callee.call(0x1700)
    elif after in ("partial-write", "unknown-write", "join"):
        if after == "join":
            callee.cbranch("skip-write", reg(RDI, 1))
        later = _key(callee, 1 if after != "unknown-write" else 0, "STORE")
        if after == "unknown-write":
            callee.ins(store(reg(RDI), const(7, 1)))
        else:
            callee.ins(add(tmp(0x100), reg(RSP), const(0x30)), store(tmp(0x100), const(7, 1)))
        if after == "join":
            callee.label("skip-write")
    else:
        # Same meaning as the original saved-pointer LOAD, but not the
        # instruction immediately following Realloc.
        callee.ins(copy(tmp(0x500), const(23)))
    reader = _key(callee, 1, "LOAD")
    loads = [add(tmp(0x100), reg(RSP), const(0x30)), load(tmp(0x200, width), tmp(0x100))]
    if multiple:
        loads.extend((add(tmp(0x300), reg(RSP), const(0x34)), load(tmp(0x400, 4), tmp(0x300))))
    callee.ins(*loads).add_rsp(0x48).ret()
    result = _analyze_units(caller, callee, models=models)
    owner, generic = result["1:1000"], result["1:1600"]
    context = owner.activations[outer]
    return generic, context, dict(outer=outer, saved=saved, realloc=realloc, reader=reader, later=later)


@pytest.mark.parametrize("width", (1, 2, 4, 8, 16))
def test_delayed_reads_of_different_widths_use_original_ssa_ranges(models, width):
    generic, context, points = _range_case(models, width=width)
    read = _read(context, points["reader"])
    (decision,) = [row for row in context.call_memory_decisions
                   if row.demand.reader == points["reader"] and row.demand.call == points["realloc"]]
    assert decision.preserved and decision.demand.span.size == width
    assert decision.demand.span == read.span and not context.proven[points["realloc"]].preserves_memory
    assert any(row.operation_key == points["reader"] and points["realloc"] in row.intervening_calls
               for row in generic.normalized.call_clobber_reads)
    assert not any(row.operation_key == points["reader"] and points["realloc"] in row.intervening_calls
                   for row in context.normalized.call_clobber_reads)
    # Wide reads may include unknown ENTRY bytes. No single-writer or full
    # read-completeness claim follows from CALL no-write.
    graph = context.normalized.dependencies
    reader = graph.node_for_key("op:" + points["reader"])
    writer = graph.node_for_key("op:" + points["saved"])
    assert writer in BackwardSliceQuery().run(context.normalized, reader).reachable_nodes


def test_multiple_loads_in_one_instruction_have_separate_range_decisions(models):
    _, context, points = _range_case(models, width=4, multiple=True)
    # Explicit operation identity, not a single-LOAD instruction pattern.
    readers = {row.demand.reader for row in context.call_memory_decisions
               if row.preserved and row.demand.call == points["realloc"] and row.demand.span.size == 4}
    assert points["reader"] in readers and len(readers) >= 2
    assert len({row.demand.span for row in context.call_memory_decisions
                if row.preserved and row.demand.reader in readers}) >= 2


@pytest.mark.parametrize("after", ("partial-write", "unknown-call", "unknown-write", "join"))
def test_no_write_of_one_call_never_erases_later_writers_calls_or_joins(models, after):
    generic, context, points = _range_case(models, after=after)
    decision = next(row for row in context.call_memory_decisions
                    if row.demand.reader == points["reader"] and row.demand.call == points["realloc"])
    assert decision.preserved
    read = _read(context, points["reader"])
    assert not any(row.operation_key == points["reader"] and points["realloc"] in row.intervening_calls
                   and any(span.overlaps(decision.demand.span) for span in row.spans)
                   for row in context.normalized.call_clobber_reads)
    if after == "unknown-call":
        assert any(row.operation_key == points["reader"] and points["later"] in row.intervening_calls
                   for row in context.normalized.call_clobber_reads)
        assert probe(context.normalized, points["reader"], (read.span,))[0][read.span] is None
    else:
        graph = context.normalized.dependencies
        target = graph.node_for_key("op:" + points["reader"])
        writer = graph.node_for_key("op:" + points["later"])
        assert writer in BackwardSliceQuery().run(context.normalized, target).reachable_nodes
        if after == "unknown-write":
            assert any(row.operation_key == points["reader"] for row in context.normalized.may_alias_reads)
        else:
            assert any(context.normalized.memory_ssa.definitions[identifier].operation_key == points["later"]
                       for fragment in read.fragments for identifier in fragment.definition_ids) or after == "join"
            if after == "join":
                assert any(context.normalized.memory_ssa.definitions[identifier].kind is MemoryDefinitionKind.JOIN
                           for fragment in read.fragments for identifier in fragment.definition_ids)


def test_nonnull_lifetime_unknown_keeps_entry_state_and_original_call_debt(models):
    generic, context, points = _range_case(models, old_pointer=0x4500)
    assert context.normalized.activation_entry.memory
    assert context.proven == generic.proven
    decision = next(row for row in context.call_memory_decisions
                    if row.demand.reader == points["reader"] and row.demand.call == points["realloc"])
    assert not decision.preserved and decision.reason == "allocation-lifetime-unproved"
    read = _read(context, points["reader"])
    assert probe(context.normalized, points["reader"], (read.span,))[0][read.span] is None


def test_missing_original_summary_inputs_refuses_entry_replay(models):
    result, points = _run(models)
    adopted = result["1:1000"].activations[points["outer"]]
    original, generic, call, _ = adopted.activation_witness
    assert len(generic.summary_inputs) == 3
    assert _call_activation.replay_activation(original, replace(generic, summary_inputs=()), call) is None


def test_direct_declared_sink_is_not_lost_by_entry_replay():
    from test_interprocedural import SINK_USE, _sink_roots

    caller = FunctionBuilder().sub_rsp(0x80).ins(add(reg(RCX), reg(RSP), const(0x30)))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x80).ret()
    callee = (FunctionBuilder(0x1600).ins(load(reg(RAX), reg(RCX)))
              .ins(copy(tmp(SINK_USE), reg(RCX))).ret())
    result = analyze_units(program_units(caller, callee), sink_roots=_sink_roots,
                           assume_entry_values_not_frame=False)
    owner, generic = result["1:1000"], result["1:1600"]
    assert generic.summary.sink_demands and not generic.origins and not generic.projected_sinks
    assert _call_activation.replay_activation(owner, generic, outer) is None
    assert outer not in owner.activations


@pytest.mark.parametrize("cut", ("trap", "conditional-jump", "unconditional-jump"))
def test_original_control_cuts_and_dependencies_survive_both_replay_layers(models, cut):
    from test_noreturn_models import ABORT, _JumpsToAbort
    from tdo_v2.image_info import ImportedSymbol
    from tdo_v2.pcodeop_models import PcodeOpModel

    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(add(reg(RCX), reg(RSP), const(0x30)), store(reg(RCX), const(0))))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x80).ret()
    callee = FunctionBuilder(0x1600) if cut == "trap" else _JumpsToAbort(entry=0x1600)
    jump = _key(callee, 0, "CBRANCH")
    if cut == "conditional-jump":
        callee.conditional.add(0)
        callee.ins(op("CBRANCH", [ram(ABORT), reg(RDI, 1)]))
    else:
        callee.cbranch("trap", reg(RDI, 1))
    callee = (callee.sub_rsp(0x48)
              .ins(copy(reg(RBX), reg(RCX)))
              .ins(add(tmp(0x100), reg(RSP), const(0x30)), store(tmp(0x100), reg(RBX)))
              .ins(load(reg(RCX), reg(RBX))).ins(copy(reg(RDX), const(16))))
    realloc = _key(callee, 2, "CALL")
    callee.call(THUNKS["realloc"])
    reader = _key(callee, 1, "LOAD")
    callee.ins(add(tmp(0x100), reg(RSP), const(0x30)), load(reg(RAX), tmp(0x100)))
    callee.add_rsp(0x48).ret()
    if cut == "trap":
        callee.label("trap")
        jump = _key(callee, 0, "CALLOTHER")
        callee.ins(op("CALLOTHER", [const(16, 4), const(3, 4)], None)).ret()
    elif cut == "unconditional-jump":
        callee.label("trap")
        jump = _key(callee, 0, "BRANCH")
        callee.unconditional.add(len(callee._rows))
        callee.ins(op("BRANCH", [ram(ABORT)]))
        callee._rows[-1].kind = "return"
    units = program_units(caller, callee)
    ns = units[0].scopes.program.evidence.translation_namespace
    marker = PcodeOpModel("x86-markers", 1,
                          frozenset({(ns.language_id, ns.major_version, ns.minor_version)}),
                          {}, {16: frozenset({3})})
    image = _image()
    image = replace(image, imports=tuple(row for row in image.imports if (1, ABORT) not in row.thunks)
                    + (ImportedSymbol("CRT", "abort", None, (), ((1, ABORT),)),))
    result = analyze_units(units, image_info=image, external_models=models, pcodeop_models=(marker,),
                           private_frame_above=40, assume_globals_disjoint_from_stack=True,
                           assume_entry_values_not_frame=False,
                           assume_opaque_callees_leave_no_stack_addresses=False,
                           assume_debug_break_traps_do_not_return=True)
    adopted = result["1:1000"].activations[outer]
    original, generic, call, _ = adopted.activation_witness
    entry = _call_activation.replay_activation(original, generic, call)
    assert entry is not None and not generic.summary.tail_exits
    assert jump in generic.summary_inputs[1 if cut == "conditional-jump" else 0]
    if cut != "conditional-jump":
        assert generic.summary.dead_exits
    dependency = ("debug-break-traps-do-not-return" if cut == "trap"
                  else "external-model:crt-win64/abort@v8")
    assert any(row.operation_key == reader and realloc in row.intervening_calls
               for row in entry.normalized.call_clobber_reads)
    refined = refine_call_memory(entry)
    assert refined.normalized is not entry.normalized
    assert any(row.preserved and row.demand.call == realloc and row.demand.reader == reader
               for row in refined.call_memory_decisions)
    for context in (entry, refined):
        assert context.summary.dead_exits == generic.summary.dead_exits
        assert len(context.summary.exits) == len(generic.summary.exits)
        assert not context.summary.tail_exits
        assert dependency in context.normalized.activation_entry.requires
        assert dependency in context.inherited_assumptions
    read = _read(refined, reader)
    values, requires = probe(refined.normalized, reader, (read.span,))
    assert type(values[read.span]) is int and dependency in requires


def test_automatic_scheduler_bounds_attempts_not_successes(monkeypatch):
    caller = FunctionBuilder().sub_rsp(0x28)
    for _ in range(10):
        caller.call(0x1600)
    caller.add_rsp(0x28).ret()
    callee = (FunctionBuilder(0x1600).sub_rsp(0x38).call(0x1700)
              .ins(add(tmp(0x100), reg(RSP), const(0x30)), load(reg(RAX), tmp(0x100)))
              .add_rsp(0x38).ret())
    attempts = []
    replay = _call_activation.replay_activation

    def watched(owner, target, call, **options):
        attempts.append((owner.key, call))
        return replay(owner, target, call, **options)

    monkeypatch.setattr(_call_activation, "replay_activation", watched)
    result = _analyze_units(caller, callee)
    assert len(attempts) == 8 and not result["1:1000"].activations


def test_memory_consumer_captures_policy_and_rejects_foreign_reader(models):
    result, points = _run(models)
    adopted = result["1:1000"].activations[points["outer"]]
    original, generic, call, _ = adopted.activation_witness
    context = _call_activation.replay_activation(original, generic, call)
    assert context is not None
    baseline = refine_call_memory(context)
    token = ENTRY_VALUES_NOT_FRAME.set(True)
    try:
        refined = refine_call_memory(context)
        assert ENTRY_VALUES_NOT_FRAME.get() is True
    finally:
        ENTRY_VALUES_NOT_FRAME.reset(token)
    assert refined.normalized.forward_inputs.entry_values_not_frame is False
    assert "entry-values-do-not-address-the-new-frame" not in refined.inherited_assumptions
    assert encode(refined.normalized) == encode(baseline.normalized)
    assert refined.summary == baseline.summary
    with pytest.raises(RefinementRefused, match="image reader"):
        refine_call_memory(context, readonly_image=object())
    assert context.proven == generic.proven and not context.call_memory_decisions


def test_equal_generic_summary_and_anchors_do_not_publish_a_context(models, monkeypatch):
    from tdo_v2 import _call_memory

    attempts = []

    def no_improvement(context, **options):
        attempts.append(context)
        generic = context.activation_witness[1]
        return replace(context, summary=generic.summary, anchors=generic.anchors)

    monkeypatch.setattr(_call_memory, "refine_call_memory", no_improvement)
    result, points = _run(models)
    assert len(attempts) == 1 and not result["1:1000"].activations
    assert result["1:1600"].normalized.activation_entry is None


def test_input_signature_freezes_unordered_anchored_condition_keys(models):
    result, points = _run(models)
    context = result["1:1000"].activations[points["outer"]]
    # Existing immutable span objects need equality, not Python ordering.
    spans = [row.demand.span for row in context.call_memory_decisions]
    first = spans[0]
    second = replace(first, start=first.start + first.size + 1)
    forward = {first: {"bytes": [1, 2]}, second: {"bytes": [3]}}
    reverse = {second: {"bytes": [3]}, first: {"bytes": [1, 2]}}
    assert _freeze(forward) == _freeze(reverse)
    reverse[second]["bytes"].append(4)
    assert _freeze(forward) != _freeze(reverse)


def test_optional_nonresource_normalization_failure_keeps_entry_context(models, monkeypatch):
    result, points = _run(models)
    adopted = result["1:1000"].activations[points["outer"]]
    original, generic, call, _ = adopted.activation_witness
    context = _call_activation.replay_activation(original, generic, call)
    assert context is not None
    # Explicit consumer-boundary refusal, not a replacement admitted body.
    monkeypatch.setattr(_call_activation, "_normalize", lambda *args, **kwargs:
                        UnresolvedNormalizedFunction(context.unit.scopes,
                            NormalizationFailureReason.MISSING_VALIDATED_OBSERVATION))
    refused = refine_call_memory(context)
    assert refused.normalized is context.normalized and refused.summary is context.summary
    assert refused.proven is context.proven and refused.activation_witness is context.activation_witness
    assert not any(row.preserved for row in refused.call_memory_decisions)
    assert any(row.reason == "replay-normalization-refused" for row in refused.call_memory_decisions)


def test_accepted_decision_dependencies_reach_state_inherited_and_probe(models, monkeypatch):
    from tdo_v2 import _call_memory

    result, points = _run(models)
    adopted = result["1:1000"].activations[points["outer"]]
    original, generic, call, _ = adopted.activation_witness
    context = _call_activation.replay_activation(original, generic, call)
    decide = _call_memory.decide_call_memory
    label = "test-only-call-memory-proof-dependency"

    def additional_dependency(*args, **kwargs):
        return tuple(replace(row, requires=tuple(sorted((*row.requires, label)))) if row.preserved else row
                     for row in decide(*args, **kwargs))

    monkeypatch.setattr(_call_memory, "decide_call_memory", additional_dependency)
    refined = refine_call_memory(context)
    assert label in refined.inherited_assumptions
    assert label in refined.normalized.activation_entry.requires
    read = _read(refined, points["reader"])
    found, requires = probe(refined.normalized, points["reader"], (read.span,))
    assert type(found[read.span]) is int and label in requires
    assert label not in context.inherited_assumptions


def test_source_capture_accepts_unhashable_reader_but_rejects_equal_foreign_reader(models):
    class Reader:
        __hash__ = None

        def __eq__(self, other):
            return isinstance(other, Reader)

        def value(self, *args):
            return None

    reader = Reader()
    result, points = _run(models, readonly_image=reader)
    owner = result["1:1000"]
    context = owner.activations[points["outer"]]
    original, generic, call, _ = context.activation_witness
    assert _call_activation.revalidate_activation(original, owner, context, readonly_image=reader)
    same = _call_activation.replay_activation(original, generic, call, readonly_image=reader)
    assert same is not None
    refined = refine_call_memory(same, readonly_image=reader)
    assert any(row.preserved for row in refined.call_memory_decisions)
    foreign = Reader()
    assert foreign == reader and foreign is not reader
    assert _call_activation.replay_activation(original, generic, call, readonly_image=foreign) is None
    with pytest.raises(RefinementRefused, match="image reader"):
        refine_call_memory(same, readonly_image=foreign)


@pytest.mark.parametrize("frame", (False, True))
@pytest.mark.parametrize("displacement,width", ((0, 8), (0, 1), (4, 8), (7, 2)))
def test_real_body_return_overlay_writes_lower_onto_the_push(frame, displacement, width):
    """The callee writes into its own return-address slot: the context keeps
    that write in its entry SSA, and lowering it is an ordinary memory run
    onto the caller's push definition (``normalize._push_row``; before the
    push was a definition the lowering dropped it and the context was
    refused, "return-overlay-writer-not-lowerable")."""
    from test_interprocedural import _check

    caller = (FunctionBuilder().sub_rsp(0x40)
              .ins(add(reg(RCX), reg(RSP), const((displacement - 8) % (1 << 64)))))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600)
    caller.ins(add(tmp(0x100), reg(RSP), const((displacement - 8) % (1 << 64))),
               load(reg(RAX, width), tmp(0x100))).add_rsp(0x40).ret()
    callee = FunctionBuilder(0x1600).ins(store(reg(RCX), const(7, width))).ret()
    result = analyze_units(program_units(caller, callee), private_frame_above=0,
                           assume_entry_values_not_frame=frame,
                           assume_opaque_callees_leave_no_stack_addresses=False)
    owner, generic = result["1:1000"], result["1:1600"]
    assert outer not in owner.activation_rejections and outer in owner.activations   # (the lowered context is used)
    context = _call_activation.replay_activation(owner, generic, outer)
    assert context is not None  # Entry transport itself is valid under both policies.
    assert any(definition.kind is MemoryDefinitionKind.DATA_WRITE
               and definition.span.start == (1 << 64) + displacement and definition.span.size == width
               for definition in context.normalized.memory_ssa.definitions)
    program = {(1, item.unit.scopes.function.entry.byte_offset): item.unit.observation for item in result.values()}
    assert _check(result, program).silent == []


def test_the_memory_consumer_output_keeps_the_slot_writer(models, monkeypatch):
    # The original projector keeps the candidate address even with CALL
    # debt. The refined context (the memory consumer's output) keeps the
    # callee's write into its return-address slot as a definition; it lowers
    # onto the caller's push (it was refused while the push was no definition).
    from tdo_v2 import _call_memory

    processed = []
    refine = _call_memory.refine_call_memory

    def consumed(context, **options):
        final = refine(context, **options)
        processed.append(final)
        return final

    monkeypatch.setattr(_call_memory, "refine_call_memory", consumed)
    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(add(reg(RCX), reg(RSP), const(0x30)), store(reg(RCX), const(0))))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x80).ret()
    callee = (FunctionBuilder(0x1600).sub_rsp(0x48)
              .ins(copy(reg(RBX), reg(RCX)))
              .ins(add(tmp(0x200), reg(RSP), const(0x48)),
                   add(tmp(0x100), reg(RSP), const(0x30)), store(tmp(0x100), tmp(0x200)))
              .ins(load(reg(RCX), reg(RBX))).ins(copy(reg(RDX), const(16))))
    realloc = _key(callee, 2, "CALL")
    callee.call(THUNKS["realloc"])
    pointer_read = _key(callee, 1, "LOAD")
    callee.ins(add(tmp(0x100), reg(RSP), const(0x30)), load(reg(RDI), tmp(0x100)))
    actual_store = _key(callee, 0, "STORE")
    callee.ins(store(reg(RDI), const(7))).add_rsp(0x48).ret()
    result = _analyze_units(caller, callee, models=models)
    owner, generic = result["1:1000"], result["1:1600"]
    assert outer not in owner.activation_rejections and outer in owner.activations   # (the lowered context is used)
    entry = _call_activation.replay_activation(owner, generic, outer)
    assert entry is not None and processed
    assert any(row.operation_key == pointer_read and realloc in row.intervening_calls
               for row in entry.normalized.call_clobber_reads)
    refined = refine_call_memory(entry)
    assert any(row.preserved and row.demand.call == realloc and row.demand.reader == pointer_read
               for row in refined.call_memory_decisions)
    assert any(definition.operation_key == actual_store and definition.span.start == (1 << 64)
               and definition.span.size == 8 for definition in refined.normalized.memory_ssa.definitions)
