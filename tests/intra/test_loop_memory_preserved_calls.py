"""CALL-containing and nested families retain only weak loop addresses.

The positive path uses real callee summaries. Direct map injection below is
the existing normalizer trust boundary, not an independently issued model.
An outside/preheader CALL is not a loop-internal memory barrier: an original
maximal CALL-free loop retains its existing visit-qualified read-from rules.
"""

from collections import Counter
from dataclasses import replace

import pytest

from synthetic import (
    DATA_BASE, RAX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder,
    add, const, copy, load, op, program_units, ram, reg, store, sub, tmp,
)
from tdo_v2 import _loop_memory
from tdo_v2.call_summary_effects import AnchoredSpan, ProvenCallEffect
from tdo_v2.function_summary import summarize_function
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
from tdo_v2.span_geometry import ByteSpan


LEAF, OTHER = 0x1800, 0x1900


def _program(*, placement="before", indexed=False, extra=None, clobber=None,
             raw_output=False, indirect=False, previous=False, entry_store=False):
    builder, keys = FunctionBuilder(), {}
    pointer, counter, flag = reg(RSI), tmp(0x6200), tmp(0x6300, 1)
    address = tmp(0x6400)

    def ins(name, *operations):
        keys[name] = (f"1:{builder.entry + len(builder._rows) * builder.stride:x}:"
                      f"{len(operations) - 1}:{operations[-1][0]}")
        builder.ins(*operations)

    def call(name="call", target=LEAF):
        pc = builder.entry + len(builder._rows) * builder.stride
        builder.call_indirect(RAX) if indirect else builder.call(target)
        if raw_output:
            old = builder._rows[-1].ops[-1]
            builder._rows[-1].ops[-1] = op(old[0], old[1], pointer)
        operation = builder._rows[-1].ops[-1]
        keys[name] = f"1:{pc:x}:{len(builder._rows[-1].ops) - 1}:{operation[0]}"

    ins("source", copy(pointer, const(0)) if indexed else load(pointer, const(DATA_BASE)))
    if indexed:
        ins("base", copy(reg(RDI), reg(RDX)))
    builder.ins(copy(counter, reg(RCX)))
    if entry_store:
        ins("entry-write", sub(tmp(0x6600), reg(RDI) if indexed else pointer, const(8)),
            store(tmp(0x6600), const(0x12345678)))
    if placement == "preheader":
        call()
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag)).label("loop")
    if placement == "before":
        call()
    if indexed:
        ins("address", add(address, pointer, reg(RDI)))
    else:
        ins("address", copy(address, pointer))
    ins("write", store(address, reg(RDX)))
    if placement == "between":
        call()
    if previous:
        ins("read", sub(tmp(0x6500), address, const(8)), load(reg(RAX), tmp(0x6500)))
    else:
        ins("read", load(reg(RAX), address))
    if placement == "after":
        call()
    if extra == "opaque":
        call("opaque", 0x1f00)
    elif extra == "calleither":
        ins("opaque", op("CALLOTHER", [const(0)]))
    elif extra == "second":
        call("second", OTHER)
    ins("update", add(pointer, pointer, const(8)))
    builder.ins(sub(counter, counter, const(1)))
    builder.cbranch("loop", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
    builder.label("done").ret()
    leaf = FunctionBuilder(entry=LEAF)
    if clobber is not None:
        leaf.ins(copy(reg(clobber, 4), const(5, 4)))
    else:
        leaf.ins(copy(reg(RAX), const(7)))
    leaf.ret()
    functions = [builder, leaf]
    if extra == "second":
        functions.append(FunctionBuilder(entry=OTHER).ins(copy(reg(RAX), const(9))).ret())
    return program_units(*functions), keys


def _analyzed(**options):
    from tdo_v2.interprocedural import analyze_units

    units, keys = _program(**options)
    results = analyze_units(units)
    owner = results["1:1000"]
    assert type(owner.normalized) is NormalizedFunction
    return owner, units[0], keys


def _generic(unit):
    normalized = FunctionNormalizer().normalize(unit)
    assert type(normalized) is NormalizedFunction
    return normalized


def _derive(normalized, unit, effects):
    evidence = unit.scopes.program.evidence
    return _loop_memory.derive_loop_memory(
        normalized.memory_unit, normalized.memory_ssa, unit.observation,
        unit.scopes.function.entry, unit.scopes.resolution_context,
        evidence.address_spaces, evidence.translation_namespace,
        proven_call_effects=effects,
    )


def _index(normalized, unit, effects):
    return _loop_memory._Index(normalized.memory_unit, normalized.memory_ssa,
        unit.observation, unit.scopes.function.entry, unit.scopes.resolution_context,
        proven_call_effects=effects)


def _span(effect, offset, width=8):
    return ByteSpan(effect.preserved[0].object_id, offset, width)


def _assert_weak(plan, keys):
    assert plan is not None and plan.families
    assert {keys["write"], keys["read"]} <= {row.operation_key for row in plan.accesses}
    assert not plan.read_from  # neither the current nor a later header visit


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("placement", ("before", "between", "after"))
def test_real_summary_preserves_only_weak_addresses_across_a_direct_call(monkeypatch, engine, placement):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    owner, _, keys = _analyzed(placement=placement)
    effect = owner.proven[keys["call"]]
    assert type(effect) is ProvenCallEffect and effect.callee == "1:1800"
    assert effect.preserves_memory and not effect.writer_conditions and not effect.control_sites
    binding = owner.normalized.memory_graph.loop_memory
    assert binding is not None
    _assert_weak(binding.plan, keys)
    assert owner.normalized.memory_ssa.unresolved_reads
    assert owner.normalized.memory_ssa.unresolved_writes
    graph = owner.normalized.dependencies
    for key in (keys["write"], keys["read"]):
        operation = graph.node_for_key("op:" + key)
        assert any(edge.kind == "loop_memory_address" for _, _, edge in graph.in_edges(operation))
    assert not any(edge.kind.startswith("loop_read_from") or edge.kind.startswith("loop_previous_read_from")
                   for _, _, edge in graph.weighted_edges())


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("placement", ("before", "after"))
def test_actual_partial_register_clobber_rejects_a_full_width_induction(monkeypatch, engine, placement):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    owner, _, keys = _analyzed(clobber=RSI, placement=placement)
    assert keys["call"] in owner.proven
    binding = owner.normalized.memory_graph.loop_memory
    assert binding is None or not any(row.operation_key in (keys["write"], keys["read"])
                                      for row in binding.plan.accesses)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_preserved_call_after_reader_still_forbids_previous_visit_value_relations(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    owner, _, keys = _analyzed(placement="after", previous=True)
    _assert_weak(owner.normalized.memory_graph.loop_memory.plan, keys)


@pytest.mark.parametrize("change", (
    "partial-preserved", "run-write", "fresh", "nonstack", "same-object", "tail-stack",
    "writer-condition", "control-site", "noreturn", "does-not-keep-memory", "callee", "site", "untyped",
))
def test_injected_effect_cannot_bypass_explicit_outputs_or_conditional_authority(change):
    owner, unit, keys = _analyzed()
    normalized, effect = _generic(unit), owner.proven[keys["call"]]
    span, other = _span(effect, RSI), _span(effect, RDI)
    conditions = ((AnchoredSpan(span, 0, 8, 1), AnchoredSpan(other, 0, 8, 1)),)
    changes = {
        "partial-preserved": dict(preserved=(_span(effect, RSI, 4),)),
        "run-write": dict(runs=(replace(effect.runs[0], writes=(span,)),)),
        "fresh": dict(fresh_registers=(span,)),
        "nonstack": dict(nonstack_results=((span, 16, "synthetic-nonstack"),)),
        "same-object": dict(same_object_registers=((span, other),)),
        "tail-stack": dict(tail_stack=(span,)),
        "writer-condition": dict(writer_conditions=conditions),
        "control-site": dict(control_sites=("1:1800:0:CALL",)),
        "noreturn": dict(noreturn=True),
        "does-not-keep-memory": dict(preserves_memory=False),
        "callee": dict(callee="1:1900"),
    }
    if change in changes:
        effect = replace(effect, **changes[change])
    effects = {keys["call"] if change != "site" else keys["read"]:
               effect if change != "untyped" else object()}
    plan = _derive(normalized, unit, effects)
    assert plan is None or not any(row.operation_key in (keys["write"], keys["read"])
                                   for row in plan.accesses)


def test_full_preserved_mask_does_not_override_a_raw_call_output():
    owner, _, _ = _analyzed()
    (unit, _), keys = _program(raw_output=True)
    normalized = _generic(unit)
    effect = next(iter(owner.proven.values()))
    span = _span(effect, RSI)
    effect = replace(effect, preserved=(span,), runs=(), fresh_registers=(), tail_stack=())
    assert _derive(normalized, unit, {keys["call"]: effect}) is None


@pytest.mark.parametrize("extra", ("opaque", "calleither"))
def test_one_unproved_or_other_call_keeps_the_whole_cyclic_region_blocked(extra):
    owner, unit, keys = _analyzed(extra=extra)
    assert keys["call"] in owner.proven
    normalized = _generic(unit)
    assert _derive(normalized, unit, {keys["call"]: owner.proven[keys["call"]]}) is None
    assert owner.normalized.memory_graph.loop_memory is None


def test_indirect_call_is_not_authorized_by_an_injected_direct_callee_effect():
    owner, _, _ = _analyzed()
    (unit, _), keys = _program(indirect=True)
    assert _derive(_generic(unit), unit, {keys["call"]: next(iter(owner.proven.values()))}) is None


def test_callee_effects_cannot_be_swapped_between_two_raw_call_sites():
    owner, unit, keys = _analyzed(extra="second")
    effects = {keys["call"]: owner.proven[keys["second"]],
               keys["second"]: owner.proven[keys["call"]]}
    assert _derive(_generic(unit), unit, effects) is None


@pytest.mark.parametrize("reverse", (False, True))
def test_call_corridor_cache_is_specific_to_register_bytes_not_just_writer_reader(reverse):
    owner, unit, keys = _analyzed(clobber=RDI)
    effect = owner.proven[keys["call"]]
    index = _index(_generic(unit), unit, {keys["call"]: effect})
    spans = (_span(effect, RSI), _span(effect, RDI))
    if reverse:
        spans = spans[::-1]
    answers = {span.start: index.call_free(keys["source"], keys["read"], span) for span in spans}
    assert answers == {RSI: True, RDI: False}
    assert not index.call_free(keys["source"], keys["read"])  # no span grants no exemption


def test_raw_stack_pointer_write_takes_priority_over_a_full_preserved_claim():
    owner, unit, keys = _analyzed()
    effect = owner.proven[keys["call"]]
    rsp = _span(effect, RSP)
    effect = replace(effect, preserved=(rsp,), runs=(), tail_stack=())
    index = _index(_generic(unit), unit, {keys["call"]: effect})
    assert not index.call_free(keys["source"], keys["read"], rsp)


@pytest.mark.parametrize("clobber", (None, RDI))
def test_preheader_call_must_preserve_the_exact_invariant_base_snapshot(clobber):
    owner, unit, keys = _analyzed(placement="preheader", indexed=True, clobber=clobber)
    plan = _derive(_generic(unit), unit, owner.proven)
    if clobber is None:
        assert plan is not None and all(family.invariant_base is not None for family in plan.families)
        assert {keys["write"], keys["read"]} <= {row.operation_key for row in plan.accesses}
    else:
        assert plan is None or not any(row.operation_key in (keys["write"], keys["read"])
                                      for row in plan.accesses)


def _original_reader_frontier(normalized, keys):
    from test_loop_memory_previous_read_from import _debts

    _debts(normalized)  # Every original unknown read/write graph edge remains.
    ssa, graph = normalized.memory_ssa, normalized.dependencies
    assert keys["read"] in {ssa.actions[row.action_id].operation_key for row in ssa.unresolved_reads}
    assert keys["write"] in {ssa.actions[row.action_id].operation_key for row in ssa.unresolved_writes}
    aliases = [node for row, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes, strict=True)
               if row.operation_key == keys["read"]]
    assert aliases
    reachable = graph.backward_reachable((graph.node_for_key("op:" + keys["read"]),))
    assert set(aliases) <= set(reachable)


def test_preheader_only_call_keeps_current_visit_value_from_the_original_loop_store():
    owner, unit, keys = _analyzed(placement="preheader", indexed=True)
    normalized = owner.normalized
    plan = normalized.memory_graph.loop_memory.plan
    rows = [row for row in plan.read_from if plan.accesses[row.reader_access].operation_key == keys["read"]]
    assert rows and all(row.visit_delta == 0 and not row.requires_backedge for row in rows)
    assert {plan.accesses[row.writer_access].operation_key for row in rows} == {keys["write"]}
    index = _index(normalized, unit, owner.proven)
    family = plan.families[plan.accesses[rows[0].reader_access].family_index]
    region = index.region_of[family.header]
    assert region not in index.nested_regions and not index.region_calls[region]
    assert index.locations[keys["call"]] not in family.blocks
    _original_reader_frontier(normalized, keys)


def test_preheader_only_call_does_not_carry_entry_store_into_previous_visit_value():
    owner, unit, keys = _analyzed(placement="preheader", indexed=True, previous=True, entry_store=True)
    normalized, ssa = owner.normalized, owner.normalized.memory_ssa
    plan = normalized.memory_graph.loop_memory.plan
    rows = [row for row in plan.read_from if plan.accesses[row.reader_access].operation_key == keys["read"]]
    assert rows and all(row.visit_delta == -1 and row.requires_backedge for row in rows)
    assert {plan.accesses[row.writer_access].operation_key for row in rows} == {keys["write"]}
    assert keys["entry-write"] not in {row.operation_key for row in plan.accesses}
    entry_action = next(identifier for identifier, action in enumerate(ssa.actions)
                        if action.operation_key == keys["entry-write"])
    assert ssa.actions[entry_action].write_definition_ids or any(
        row.action_id == entry_action for row in ssa.unresolved_writes)
    family = plan.families[plan.accesses[rows[0].reader_access].family_index]
    assert family.entry_edges and family.backedge_edges
    assert all(edge.predecessor_key not in family.blocks for edge in family.entry_edges)
    assert all(edge.predecessor_key in family.blocks for edge in family.backedge_edges)
    index = _index(normalized, unit, owner.proven)
    assert index.region_of[family.header] not in index.nested_regions
    assert not index.region_calls[index.region_of[family.header]]
    # There is deliberately no unconditional/current row for the first visit,
    # even though a concrete earlier STORE initializes those entry bytes.
    _original_reader_frontier(normalized, keys)


def test_receipt_pins_an_immutable_effect_map_snapshot_not_the_mutable_dictionary():
    owner, unit, keys = _analyzed()
    normalized = _generic(unit)
    effects = dict(owner.proven)
    plan = _derive(normalized, unit, effects)
    _assert_weak(plan, keys)
    snapshot = next(row for row in plan._proof.inputs if type(row) is tuple
                    and (keys["call"], effects[keys["call"]]) in row)
    assert snapshot == ((keys["call"], effects[keys["call"]]),)
    effects.clear()
    effects[keys["call"]] = object()
    _loop_memory.validate_loop_memory(plan, normalized.memory_ssa)
    assert snapshot[0][1] is owner.proven[keys["call"]]
    assert _derive(normalized, unit, effects) is None


@pytest.mark.parametrize("gap", (False, True))
def test_preserved_chunks_must_jointly_cover_every_requested_byte(gap):
    owner, unit, keys = _analyzed()
    normalized, effect = _generic(unit), owner.proven[keys["call"]]
    # Deliberately reverse their order; coverage is a union, not first-row selection.
    effect = replace(effect, preserved=(_span(effect, RSI + 4, 4), _span(effect, RSI, 3 if gap else 4)))
    plan = _derive(normalized, unit, {keys["call"]: effect})
    if gap:
        assert plan is None
    else:
        _assert_weak(plan, keys)


def test_unresolved_raw_register_write_is_not_silently_ignored(monkeypatch):
    from tdo_v2._scope_contracts import VarnodeKindCode

    owner, unit, keys = _analyzed()
    normalized = _generic(unit)
    span = _loop_memory._Index.span

    def unresolved_stack_write(self, value):
        if value.kind is VarnodeKindCode.REGISTER and value.coordinate.byte_offset == RSP:
            return None
        return span(self, value)

    monkeypatch.setattr(_loop_memory._Index, "span", unresolved_stack_write)
    assert _derive(normalized, unit, owner.proven) is None


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_mixed_call_free_and_call_containing_families_skip_only_the_latter_values(monkeypatch, engine):
    from tdo_v2.interprocedural import analyze_units

    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    builder, keys = FunctionBuilder(), {}
    counter, flag = tmp(0x6800), tmp(0x6900, 1)
    for number in range(2):
        builder.ins(load(reg(RSI), const(DATA_BASE)), copy(counter, reg(RCX)))
        builder.cbranch(f"done{number}", flag, op("INT_EQUAL", [counter, const(0)], flag))
        builder.label(f"loop{number}")
        if number:
            builder.call(LEAF)
        for name, operation in (("write", store(reg(RSI), reg(RDX))),
                                ("read", load(reg(RAX), reg(RSI)))):
            keys[number, name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:{operation[0]}"
            builder.ins(operation)
        builder.ins(add(reg(RSI), reg(RSI), const(8)), sub(counter, counter, const(1)))
        builder.cbranch(f"loop{number}", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
        builder.label(f"done{number}")
    builder.ret()
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), const(7))).ret()
    owner = analyze_units(program_units(builder, leaf))["1:1000"]
    assert type(owner.normalized) is NormalizedFunction
    plan = owner.normalized.memory_graph.loop_memory.plan
    assert len(plan.families) == 2
    assert set(keys.values()) <= {row.operation_key for row in plan.accesses}
    assert any(plan.accesses[row.reader_access].operation_key == keys[0, "read"] and row.visit_delta == 0
               for row in plan.read_from)
    assert not any(plan.accesses[row.reader_access].operation_key == keys[1, "read"] for row in plan.read_from)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_weak_call_relations_do_not_change_original_ssa_debts_or_summary(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    owner, unit, keys = _analyzed()
    normalizer = FunctionNormalizer()
    derive = _loop_memory.derive_loop_memory

    def strict(*args, **kwargs):
        kwargs.pop("proven_call_effects", None)
        return derive(*args[:7], **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(_loop_memory, "derive_loop_memory", strict)
        before = normalizer.normalize(unit, proven_call_effects=owner.proven)
    after = normalizer.normalize(unit, proven_call_effects=owner.proven)
    assert type(before) is type(after) is NormalizedFunction
    assert before.memory_graph.loop_memory is None
    _assert_weak(after.memory_graph.loop_memory.plan, keys)
    assert before.memory_ssa == after.memory_ssa
    for field in ("call_clobber_reads", "may_alias_reads", "forward_memory_proofs", "forward_memory_requires"):
        assert getattr(before, field) == getattr(after, field)
    assert summarize_function(before, unit.observation) == summarize_function(after, unit.observation)

    def original_edges(normalized):
        graph = normalized.dependencies
        return Counter((graph.node(source).key, graph.node(target).key, edge)
                       for source, target, edge in graph.weighted_edges()
                       if edge.kind not in ("loop_memory_address", "loop_possible_read", "loop_possible_write"))

    assert original_edges(before) == original_edges(after)


def test_old_call_free_current_and_previous_visit_value_relations_are_unchanged():
    from test_loop_memory_read_from import _fixture as current
    from test_loop_memory_previous_read_from import _fixture as previous

    for fixture, delta in ((current, 0), (previous, -1)):
        normalized, _, keys = fixture()
        plan = normalized.memory_graph.loop_memory.plan
        assert any(row.visit_delta == delta and plan.accesses[row.reader_access].operation_key == keys["read"]
                   for row in plan.read_from)


def _nested_program(*, shape="single", updates=1, outside_call=False, child_call=False, clobber=None):
    """Original nested/sibling CFGs; no synthetic SCC or flow-edge injection."""
    builder, keys = FunctionBuilder(), {}
    outer, inner, flag = tmp(0x7000), tmp(0x7100), tmp(0x7200, 1)

    def ins(name, *operations):
        keys[name] = (f"1:{builder.entry + len(builder._rows) * builder.stride:x}:"
                      f"{len(operations) - 1}:{operations[-1][0]}")
        builder.ins(*operations)

    builder.ins(copy(outer, reg(RCX)))
    builder.cbranch("done", flag, op("INT_EQUAL", [outer, const(0)], flag))
    builder.label("outer")
    for number in range(2 if shape == "siblings" else 1):
        prefix = f"child{number}"
        ins(prefix + "-entry", load(reg(RSI), const(DATA_BASE)))
        builder.ins(copy(inner, reg(RDX)))
        builder.cbranch(prefix + "-done", flag, op("INT_EQUAL", [inner, const(0)], flag))
        if shape == "multiple-entries":
            # The parent can enter the child's header OR its body directly.
            builder.cbranch(prefix + "-body", flag, op("INT_EQUAL", [reg(RDI), const(0)], flag))
        elif shape == "multiple-preheaders":
            builder.cbranch(prefix + "-right", flag, op("INT_EQUAL", [reg(RDI), const(0)], flag))
            builder.ins(copy(tmp(0x7300), const(1))).branch(prefix + "-header")
            builder.label(prefix + "-right").ins(copy(tmp(0x7300), const(2))).branch(prefix + "-header")
        builder.label(prefix + "-header")
        ins(prefix + "-header", copy(tmp(0x7400), reg(RSI)))
        if child_call:
            builder.call(LEAF)
        builder.label(prefix + "-body")
        ins(prefix + "-write", store(reg(RSI), reg(RDX)))
        ins(prefix + "-read", load(reg(RAX), reg(RSI)))
        if updates != 1:
            builder.cbranch(prefix + "-special", flag, op("INT_EQUAL", [inner, const(2)], flag))
            ins(prefix + "-update", add(reg(RSI), reg(RSI), const(8)))
            builder.branch(prefix + "-latch").label(prefix + "-special")
            for extra in range(updates):
                ins(prefix + f"-special-update{extra}", add(reg(RSI), reg(RSI), const(8)))
            builder.branch(prefix + "-latch")
        else:
            ins(prefix + "-update", add(reg(RSI), reg(RSI), const(8)))
        builder.label(prefix + "-latch").ins(sub(inner, inner, const(1)))
        builder.cbranch(prefix + "-header", flag, op("INT_NOTEQUAL", [inner, const(0)], flag))
        builder.label(prefix + "-done")
    if outside_call:
        pc = builder.entry + len(builder._rows) * builder.stride
        builder.call(LEAF)
        keys["outer-call"] = f"1:{pc:x}:2:CALL"
    builder.ins(sub(outer, outer, const(1)))
    builder.cbranch("outer", flag, op("INT_NOTEQUAL", [outer, const(0)], flag))
    builder.label("done").ret()
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX if clobber is None else clobber), const(7))).ret()
    return program_units(builder, leaf), keys


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("call_site", (None, "parent", "child"))
def test_nested_single_entry_family_is_weak_even_without_a_call(monkeypatch, engine, call_site):
    from tdo_v2.interprocedural import analyze_units

    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    units, keys = _nested_program(outside_call=call_site == "parent", child_call=call_site == "child")
    owner = analyze_units(units)["1:1000"]
    assert type(owner.normalized) is NormalizedFunction
    binding = owner.normalized.memory_graph.loop_memory
    assert binding is not None
    plan = binding.plan
    assert len(plan.families) == 1
    assert {keys["child0-write"], keys["child0-read"]} <= {row.operation_key for row in plan.accesses}
    assert not plan.read_from
    index = _index(owner.normalized, units[0], owner.proven)
    region = index.region_of[plan.families[0].header]
    assert region in index.nested_regions
    assert bool(index.region_calls[region]) == (call_site == "child")
    assert owner.normalized.memory_ssa.unresolved_reads and owner.normalized.memory_ssa.unresolved_writes


def test_child_corridor_cannot_ignore_a_parent_call_before_the_childs_next_visit():
    from tdo_v2.interprocedural import analyze_units

    units, keys = _nested_program(outside_call=True, clobber=RSI)
    owner = analyze_units(units)["1:1000"]
    normalized = _generic(units[0])
    effect = owner.proven[keys["outer-call"]]
    index = _index(normalized, units[0], owner.proven)
    writer, reader = keys["child0-header"], keys["child0-read"]
    first, last = index.locations[writer], index.locations[reader]
    child = index.region_of[first]
    component = index.component_of[first]
    assert index.region_of[last] == child and child in index.nested_regions
    assert index.component_of[last] == component
    assert keys["outer-call"] not in index.region_calls[child]
    assert keys["outer-call"] in index.component_calls[component]
    assert not index.call_free(writer, reader, _span(effect, RSI))
    # This fixture explicitly reloads RSI on every outer entry. That fresh
    # snapshot can still support a child recurrence; it cannot certify the
    # earlier definition/use corridor across the parent's CALL.
    plan = _derive(normalized, units[0], owner.proven)
    assert plan is not None and not plan.read_from
    assert {normalized.memory_ssa.definitions[identifier].operation_key
            for family in plan.families for edge in family.entry_edges
            for identifier in edge.definition_ids} == {keys["child0-entry"]}


@pytest.mark.parametrize("shape", ("multiple-entries", "multiple-preheaders"))
def test_nested_child_keeps_original_single_entry_and_single_preheader_requirements(shape):
    units, keys = _nested_program(shape=shape)
    normalized = _generic(units[0])
    binding = normalized.memory_graph.loop_memory
    assert binding is None or not any(row.operation_key in (keys["child0-write"], keys["child0-read"])
                                      for row in binding.plan.accesses)


@pytest.mark.parametrize("updates", (0, 2))
def test_nested_child_requires_exactly_one_pointer_update_on_every_return_path(updates):
    units, keys = _nested_program(updates=updates)
    normalized = _generic(units[0])
    binding = normalized.memory_graph.loop_memory
    assert binding is None or not any(row.operation_key in (keys["child0-write"], keys["child0-read"])
                                      for row in binding.plan.accesses)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_nested_siblings_using_the_same_register_keep_distinct_occurrence_evidence(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    units, keys = _nested_program(shape="siblings")
    normalized = _generic(units[0])
    plan = normalized.memory_graph.loop_memory.plan
    assert len(plan.families) == 2 and not plan.read_from
    assert len({family.span for family in plan.families}) == 1
    assert len({family.identity for family in plan.families}) == 2
    assert len({family.header for family in plan.families}) == 2
    assert len({family.preheader for family in plan.families}) == 2
    assert len({family.entry_edges for family in plan.families}) == 2
    assert len({family.backedge_edges for family in plan.families}) == 2
    assert set(plan.families[0].blocks).isdisjoint(plan.families[1].blocks)
    for number in range(2):
        accesses = [row for row in plan.accesses if row.operation_key in
                    (keys[f"child{number}-write"], keys[f"child{number}-read"])]
        assert len(accesses) == 2 and len({row.family_index for row in accesses}) == 1
