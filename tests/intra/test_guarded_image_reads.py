"""Finite image alternatives preserve their original guard and byte evidence.

These are conditional graph relations, not a replacement for memory SSA or
permission to execute a numeric consumer by choosing the first alternative.
No fixture uses a corpus function name, jump-table address, or ABI contract.
"""

from collections import Counter
from dataclasses import replace

import pytest

from pcode_interpreter import Entry, Interpreter
from synthetic import (
    CONST, DATA_BASE, RAM, REG, RAX, RCX, RDI, RDX, RSP, FunctionBuilder,
    add, const, copy, load, op, program_units, reg, store, tmp,
)
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.image_info import BlockPermissions, ImageInfo, ImportedSymbol, ReadOnlyImage
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


TABLE = DATA_BASE + 0x180
VALUES = (0xfffffff0, 0, 0x7fffffff, 0x80000000, 0xfedcba98, 0x10203040)


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def _engine(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)


def _fixture(variant="base", *, bound=4, base=TABLE, polarity="false", form="mul", bits=32):
    builder, keys = FunctionBuilder(), {}
    selector = reg(RCX, bits // 8)
    wide, scaled, address, flag = tmp(0x6000), tmp(0x6010), tmp(0x6020), tmp(0x6030, 1)
    slot, first, second = tmp(0x6040), tmp(0x6050, bits // 8), tmp(0x6060, bits // 8)
    reload = variant in ("reload", "rewrite", "partial-write", "alias-write", "call", "call-split", "call-same")

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations)-1}:{operations[-1][0]}"
        builder.ins(*operations)

    if reload:
        builder.sub_rsp(0x40).ins(add(slot, reg(RSP), const(0x10)), store(slot, selector))
        pointer = slot
        if variant in ("call-split", "call-same"):
            # One pointer in two registers, then a CALL before BOTH loads.
            builder.ins(copy(reg(RDI), slot), copy(reg(RDX), slot))
            builder.call(0x1f00)
            pointer = reg(RDI)
        ins("guard_reload", load(first, pointer))
        selector = first
    if variant == "bypass":
        builder.cbranch("accepted", reg(RDX, 1))
    predicate = selector
    if variant == "guard-wrap":
        predicate = tmp(0x6070, bits // 8)
        ins("predicate", add(predicate, selector, const(1, bits // 8)))
    elif variant == "signed-high":
        predicate = tmp(0x6070, bits // 8)
        ins("predicate", op("INT_XOR", [selector, const(1 << (bits - 1), bits // 8)], predicate))
    compare = "INT_SLESSEQUAL" if variant == "signed-guard" else "INT_LESSEQUAL"
    if polarity == "false" and variant != "signed-guard":
        compare, inputs, destination = "INT_LESS", [const(bound, bits // 8), predicate], "done"
    else:
        inputs, destination = [predicate, const(bound, bits // 8)], "accepted"
    keys["guard"] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:1:CBRANCH"
    builder.cbranch(destination, flag, op(compare, inputs, flag))
    if destination == "accepted":
        builder.branch("done")
    builder.label("accepted")
    keys["success"] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}"
    if variant == "redefined":
        ins("change", copy(selector, const(7, bits // 8)))
    elif variant == "other-selector":
        selector = reg(RDX, bits // 8)
    if reload:
        if variant in ("rewrite", "partial-write"):
            ins("change", store(slot, const(7, 1 if variant == "partial-write" else bits // 8)))
        elif variant == "alias-write":
            ins("change", store(reg(RDI), const(7, 4)))
        elif variant == "call":
            builder.call(0x1f00)
        ins("address_reload", load(second, reg(RDX) if variant == "call-split"
                                  else reg(RDI) if variant == "call-same" else slot))
        selector = second
    if bits < 64:
        ins("extend", op("INT_SEXT" if variant in ("sign-extend", "signed-high") else "INT_ZEXT", [selector], wide))
    else:
        ins("extend", copy(wide, selector))
    if form == "or":
        ins("or", op("INT_OR", [wide, const(1)], wide))
    factor = const(2 if form == "shift" else 4)
    if form == "copied-scale":   # the scale copied into a temporary first (Astra review: still a constant)
        factor = tmp(0x6080)
        ins("scale_const", copy(factor, const(4)))
    ins("scale", op("INT_LEFT" if form == "shift" else "INT_MULT", [wide, factor], scaled))
    ins("address", add(address, const(base), scaled))
    ins("read", load(reg(RAX, 4), address))
    builder.label("done").ret()
    (unit,) = program_units(builder)
    return unit, keys


def _expected(*, bound=4, base=TABLE, form="mul", variant="base", bits=32):
    selectors = tuple(range(bound + 1))
    if variant == "guard-wrap":
        selectors = (0, 1, 2, 3, (1 << bits) - 1)
    elif variant == "signed-high":
        selectors = tuple((1 << (bits - 1)) + number for number in range(bound + 1))
    return tuple((index, (base + ((index - (1 << bits)) if variant == "signed-high" else
                                 (index | 1) if form == "or" else index) * 4) % (1 << 64),
                  VALUES[((index | 1) if form == "or" else index) % len(VALUES)]) for index in selectors)


def _image(expected, change=None):
    # Separate exact blocks also exercise modular addresses on both sides of
    # zero without making a wrapped ByteSpan or fabricating unmapped bytes.
    by_address = {address: value for _, address, value in expected}
    imports = ()
    if change == "iat":
        imports = (ImportedSymbol("fixture.dll", "mutable_slot", None,
                                  ((RAM, sorted(by_address)[-1]),), ()),)
    blocks, payloads = [], {}
    for number, (address, value) in enumerate(sorted(by_address.items())):
        if change == "missing" and number == len(by_address) - 1:
            continue
        blocks.append(BlockPermissions(RAM, address, 4, "not_a_semantic_section_name", True,
                                       change == "writable", False, change == "volatile",
                                       change != "uninitialized"))
        payloads[RAM, address] = value.to_bytes(4, "little")
    info = ImageInfo("synthetic", tuple(blocks), imports, (), ())
    return ReadOnlyImage.from_bytes(info, payloads)


def _normalize(variant="base", *, image_change=None, **options):
    unit, keys = _fixture(variant, **options)
    expected = _expected(variant=variant, **{key: value for key, value in options.items() if key != "polarity"})
    image = _image(expected, image_change)
    normalized = FunctionNormalizer().normalize(unit, readonly_image=image)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit, keys, expected, image


def _rows(normalized, reader):
    binding = normalized.memory_graph.image_reads
    return () if binding is None else tuple(row for row in binding.plan.reads if row.operation_key == reader)


def _typed_candidates(normalized, row):
    graph, ssa, memory = normalized.dependencies, normalized.memory_ssa, normalized.memory_graph
    binding = memory.image_reads
    start = sum(len(item.candidates) for item in binding.plan.reads[:binding.plan.reads.index(row)])
    load_node = graph.node_for_key("op:" + row.operation_key)
    selector = ssa.definitions[row.selector_definition_id]
    assert selector.span.contains(row.selector_span)
    address = ssa.definitions[row.address_definition_id]
    assert address.operation_key is not None
    assert any(ssa.definitions[index].span == row.output_span for action in ssa.actions
               if action.operation_key == row.operation_key for index in action.write_definition_ids)
    for offset, candidate in enumerate(row.candidates, start):
        source, effect = binding.source_nodes[offset], binding.candidate_nodes[offset]
        assert graph.node(source).kind is NodeKind.EFFECT and graph.node(source).label == "readonly_image_bytes"
        assert graph.node(effect).kind is NodeKind.EFFECT
        assert graph.node(effect).label == "guarded_image_read_alternative"
        assert any(graph.node(origin).kind is NodeKind.CONSTANT and edge.kind == "guarded_image_value"
                   and edge.span == candidate.span for origin, _, edge in graph.in_edges(source))
        assert any(target == effect and edge.kind == "guarded_image_value" and edge.span == candidate.span
                   for _, target, edge in graph.out_edges(source))
        assert any(target == load_node and edge.kind == "guarded_image_read" and edge.span == row.output_span
                   for _, target, edge in graph.out_edges(effect))
        assert any(target == effect and edge.kind == "guarded_image_selector" and edge.span == row.selector_span
                   for _, target, edge in graph.out_edges(memory.definition_nodes[row.selector_definition_id]))
        assert any(target == effect and edge.kind == "guarded_image_witness"
                   for _, target, edge in graph.out_edges(memory.definition_nodes[row.address_definition_id]))
        for key in (row.guard, *row.reloads):
            assert any(target == effect and edge.kind == "guarded_image_witness"
                       for _, target, edge in graph.out_edges(graph.node_for_key("op:" + key)))


def _execute(unit, keys, expected, image, selectors, *, bits=32):
    mapping = {index: (address, value) for index, address, value in expected}
    for index in selectors:
        vm = Interpreter(unit.observation, constant_space=CONST, seed=0,
                         image=lambda space, address: image.value(space, address, 1))
        vm.preset(REG, RSP, 8, 0x70000000)
        vm.preset(REG, RCX, bits // 8, index)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        assert (keys["read"] in run.executed) == (index in mapping)
        if index not in mapping:
            continue
        address, value = mapping[index]
        final = vm.final_bytes()
        assert sum(final[REG, RAX + byte][0] << (8 * byte) for byte in range(4)) == value
        actual = {(dep.offset, dep.writer) for dep in run.dependencies
                  if dep.reader == keys["read"] and dep.space_id == RAM}
        assert actual == {(address + byte, Entry(RAM, address + byte)) for byte in range(4)}


@pytest.mark.parametrize("polarity", ("false", "true"))
@pytest.mark.parametrize("form", ("mul", "shift", "or", "copied-scale"))
def test_original_unsigned_guard_and_exact_arithmetic_select_real_image_bytes(polarity, form):
    normalized, unit, keys, expected, image = _normalize(polarity=polarity, form=form)
    (row,) = _rows(normalized, keys["read"])
    assert row.guard == keys["guard"]
    assert row.success_edge == (":".join(keys["guard"].split(":")[:2]), keys["success"])
    assert {(item.selector, item.span.start, item.value) for item in row.candidates} == set(expected)
    assert all(item.span.size == row.output_span.size == 4 for item in row.candidates)
    _typed_candidates(normalized, row)
    # Values are selected by the unmodified raw p-code and image, not by the
    # candidate enumeration. Out-of-range selectors do not execute the LOAD.
    _execute(unit, keys, expected, image, (0, 1, 2, 3, 4, 5, 0xffffffff))


def test_two_original_reloads_of_one_unchanged_slot_keep_their_evidence():
    normalized, unit, keys, expected, image = _normalize("reload")
    (row,) = _rows(normalized, keys["read"])
    assert set(row.reloads) == {keys["guard_reload"], keys["address_reload"]}
    _typed_candidates(normalized, row)
    _execute(unit, keys, expected, image, (0, 4, 5, 0xffffffff))


@pytest.mark.parametrize("variant", ("bypass", "redefined", "other-selector", "rewrite", "partial-write",
                                     "alias-write", "call", "call-split", "signed-guard"))
def test_a_guard_does_not_certify_a_bypassing_or_different_value(variant):
    normalized, _, keys, _, _ = _normalize(variant)
    assert not _rows(normalized, keys["read"])


def test_one_register_reloaded_after_a_call_is_still_one_address():
    # The CALL may change the register, but both loads read its one current
    # value (no write between them): the reload proof keeps that corridor.
    normalized, _, keys, _, _ = _normalize("call-same")
    (row,) = _rows(normalized, keys["read"])
    assert set(row.reloads) == {keys["guard_reload"], keys["address_reload"]}


@pytest.mark.parametrize("change", ("missing", "writable", "volatile", "uninitialized", "iat"))
def test_every_possible_table_read_needs_actual_stable_mapped_bytes(change):
    normalized, _, keys, _, _ = _normalize(image_change=change)
    assert not _rows(normalized, keys["read"])


def test_candidate_cap_refuses_the_whole_fact_not_a_partial_table():
    normalized, _, keys, _, _ = _normalize(bound=8)
    assert not _rows(normalized, keys["read"])


@pytest.mark.parametrize("variant,options", (("base", {"base": (1 << 64) - 8}),
                                           ("guard-wrap", {}), ("base", {"bits": 64}),
                                           ("sign-extend", {}), ("signed-high", {})))
def test_exact_bitvector_width_and_wrap_are_not_host_integer_arithmetic(variant, options):
    normalized, unit, keys, expected, image = _normalize(variant, **options)
    (row,) = _rows(normalized, keys["read"])
    assert {(item.selector, item.span.start, item.value) for item in row.candidates} == set(expected)
    _typed_candidates(normalized, row)
    accepted = [index for index, _, _ in expected]
    _execute(unit, keys, expected, image, (*accepted, 5), bits=options.get("bits", 32))


@pytest.mark.parametrize("change", ("value", "span", "guard", "source-node"))
def test_binding_validation_rejects_changed_image_fact_or_source(change):
    normalized, _, keys, _, _ = _normalize()
    binding = normalized.memory_graph.image_reads
    (row,) = _rows(normalized, keys["read"])
    with pytest.raises((ValueError, TypeError)):
        if change == "source-node":
            forged = replace(binding, source_nodes=(normalized.dependencies.node_for_key("op:" + keys["read"]),
                                                     *binding.source_nodes[1:]))
        else:
            candidate = row.candidates[0]
            if change == "guard":
                altered = replace(row, guard=keys["address"])
            else:
                altered_candidate = replace(candidate, value=candidate.value ^ 1) if change == "value" else replace(
                    candidate, span=replace(candidate.span, start=candidate.span.start + 1))
                altered = replace(row, candidates=(altered_candidate, *row.candidates[1:]))
            forged = replace(binding, plan=replace(binding.plan, reads=(altered,)))
        replace(normalized, memory_graph=replace(normalized.memory_graph, image_reads=forged))


def test_no_readonly_input_issues_no_image_relations():
    unit, keys = _fixture()
    normalized = FunctionNormalizer().normalize(unit)
    assert not _rows(normalized, keys["read"])


def test_an_issued_graph_cannot_drop_the_readonly_policy():
    normalized, _, _, _, _ = _normalize()
    assert normalized.memory_graph.image_reads is not None
    with pytest.raises(ValueError, match="readonly-image"):
        replace(normalized, assumes_readonly_image_constant=False)


@pytest.mark.parametrize("excluded", ("read", "scale", "guard", "guard_reload", "extend"))
def test_overridden_semantics_are_not_reinterpreted_as_raw_arithmetic(monkeypatch, excluded):
    from tdo_v2 import _guarded_image_reads

    original = _guarded_image_reads.derive_guarded_image_reads
    unit, keys = _fixture("reload")
    key = keys.get(excluded, "not-an-original-operation")

    def derive(*args, **kwargs):
        return original(*args, **{**kwargs, "excluded": frozenset((key,))})

    monkeypatch.setattr(_guarded_image_reads, "derive_guarded_image_reads", derive)
    normalized = FunctionNormalizer().normalize(unit, readonly_image=_image(_expected()))
    assert not _rows(normalized, keys["read"])


def test_unrelated_exclusion_is_derivable_but_must_match_the_consumer_policy():
    from tdo_v2._guarded_image_reads import derive_guarded_image_reads, validate_guarded_image_reads

    normalized, _, keys, _, _ = _normalize("reload")
    # A stricter exclusion can still derive the relation, but it is not a
    # license to reuse a plan under a different normalized policy.
    inputs = normalized.memory_graph.image_reads.plan._proof.inputs
    plan = derive_guarded_image_reads(inputs[0], normalized.memory_ssa, *inputs[1:-1],
                                      excluded=frozenset({"not-an-original-operation"}))
    assert plan is not None and any(row.operation_key == keys["read"] for row in plan.reads)
    with pytest.raises(ValueError, match="unchanged memory"):
        validate_guarded_image_reads(plan, normalized.memory_ssa, normalized=normalized)


@pytest.mark.parametrize("variant", ("base", "reload"))
@pytest.mark.parametrize("route", ("injected", "stitched"))
def test_numeric_consumers_use_only_explicit_validated_image_ports(monkeypatch, variant, route):
    from tdo_v2 import _guarded_image_reads
    from tdo_v2.operation_records import Ineligible, StitchContext, eligibility, evaluate, root_record

    after, unit, keys, _, image = _normalize(variant)
    assert _rows(after, keys["read"])
    with monkeypatch.context() as disabled:
        disabled.setattr(_guarded_image_reads, "derive_guarded_image_reads", lambda *a, **k: None)
        before = FunctionNormalizer().normalize(unit, readonly_image=image)
    results, refusals, calls = [], [], []

    def entry(node):
        calls.append(node)
        if isinstance(node, tuple):
            assert node == ("memory", RAM, TABLE + 3 * 4, 4)
            # With no proved image port the old consumer still needs RAM.
            return 0x13579bdf
        assert node["register"]["offset"] == RCX
        return 3

    for normalized in (before, after):
        seeds = [(normalized.memory_graph.definition_nodes[i], (d.span,))
                 for i, d in enumerate(normalized.memory_ssa.definitions) if d.operation_key == keys["read"]]
        record = root_record(normalized, unit, seeds, stitch=StitchContext({}, assumptions=()))
        refusals.append(eligibility(record, route=route))
        if normalized is before and variant == "reload":
            with pytest.raises(Ineligible, match="debt"):
                evaluate(record, entry, route=route)
        else:
            results.append(evaluate(record, entry, route=route))
    if variant == "reload":
        assert refusals == ["debt", None] and results == [{VALUES[3]}]
        assert not any(isinstance(node, tuple) for node in calls)
    else:
        assert refusals == [None, None] and results == [{0x13579bdf}, {VALUES[3]}]
        assert calls.count(("memory", RAM, TABLE + 3 * 4, 4)) == 1


@pytest.mark.parametrize("position", ("after-read", "unsatisfiable-success"))
def test_only_a_preceding_reached_success_edge_can_supply_a_domain(position):
    builder = FunctionBuilder()
    wide, address, flag = tmp(0x7100), tmp(0x7110), tmp(0x7120, 1)
    operations = (op("INT_ZEXT", [reg(RCX, 4)], wide), op("INT_MULT", [wide, const(4)], address),
                  add(address, const(TABLE), address), load(reg(RAX, 4), address))
    if position == "after-read":
        reader = "1:1000:3:LOAD"
        builder.ins(*operations)
        builder.cbranch("accepted", flag, op("INT_LESSEQUAL", [reg(RCX, 4), const(4, 4)], flag))
        builder.branch("done").label("accepted").ins(copy(reg(RDX, 4), const(1, 4)))
    else:
        builder.cbranch("accepted", flag, op("INT_LESS", [reg(RCX, 4), const(0, 4)], flag))
        builder.branch("done").label("accepted")
        reader = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:3:LOAD"
        builder.ins(*operations)
    builder.label("done").ret()
    (unit,) = program_units(builder)
    image = _image(_expected())
    normalized = FunctionNormalizer().normalize(unit, readonly_image=image)
    assert not _rows(normalized, reader)
    for selector in (0, 4, 5, 0xffffffff):
        vm = Interpreter(unit.observation, constant_space=CONST, seed=0,
                         image=lambda space, address: image.value(space, address, 1))
        vm.preset(REG, RSP, 8, 0x70000000)
        vm.preset(REG, RCX, 4, selector)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        assert (reader in run.executed) == (position == "after-read")


@pytest.mark.parametrize("outcome", ("unknown", "budget-refusal"))
def test_solver_refusal_after_a_candidate_cannot_publish_a_partial_domain(monkeypatch, outcome):
    import z3
    from tdo_v2 import _guarded_image_reads

    original, calls = _guarded_image_reads._Budget.check, []

    def stop_after_one(self, solver):
        calls.append(None)
        if len(calls) == 2:
            if outcome == "budget-refusal":
                raise _guarded_image_reads._Refused()
            # Solver timeouts use this same unknown outcome. The test does
            # not depend on host timing to reproduce a partial enumeration.
            return z3.unknown
        return original(self, solver)

    monkeypatch.setattr(_guarded_image_reads._Budget, "check", stop_after_one)
    normalized, _, keys, _, _ = _normalize()
    assert len(calls) == 2 and not _rows(normalized, keys["read"])


@pytest.mark.parametrize("missing", ("guarded_image_value", "guarded_image_read", "guarded_image_selector"))
def test_topology_validation_does_not_accept_missing_typed_relations(missing):
    from tdo_v2.graph import RustworkxDependencyGraph
    from tdo_v2.memory_graph import _validate_materialized_local_memory_ssa

    normalized, _, _, _, _ = _normalize()
    original, omitted = normalized.dependencies, False
    graph = RustworkxDependencyGraph()
    for identifier in range(original.node_count):
        assert graph.add_node(original.node(identifier)) == identifier
    for source, target, edge in original.weighted_edges():
        if not omitted and edge.kind == missing:
            omitted = True
            continue
        graph.add_edge(source, target, edge)
    assert omitted
    with pytest.raises((ValueError, TypeError)):
        _validate_materialized_local_memory_ssa(graph, normalized.memory_ssa, normalized.memory_graph)
    _validate_materialized_local_memory_ssa(original, normalized.memory_ssa, normalized.memory_graph)


def test_optional_image_relations_keep_original_ssa_summary_candidates_and_debts(monkeypatch):
    from tdo_v2 import _guarded_image_reads
    from tdo_v2.function_summary import summarize_function

    after, unit, keys, _, image = _normalize("reload")
    assert _rows(after, keys["read"])
    with monkeypatch.context() as disabled:
        disabled.setattr(_guarded_image_reads, "derive_guarded_image_reads", lambda *args, **kwargs: None)
        before = FunctionNormalizer().normalize(unit, readonly_image=image)
    assert isinstance(before, NormalizedFunction) and before.memory_graph.image_reads is None
    for field in ("memory_ssa", "memory_unit", "may_alias_reads", "call_clobber_reads", "uncertain_writers",
                  "forward_memory_proofs", "load_value_proofs"):
        assert getattr(before, field) == getattr(after, field)
    expected_uses = {("readonly-image-data-is-constant", "normalize", f"{RAM:x}:{candidate.span.start:x}")
                     for row in after.memory_graph.image_reads.plan.reads for candidate in row.candidates}
    assert set(before.premise_uses) <= set(after.premise_uses)
    assert set(after.premise_uses) - set(before.premise_uses) == expected_uses

    def old_edges(normalized):
        graph = normalized.dependencies
        return Counter((graph.node(source).key, graph.node(target).key, edge)
                       for source, target, edge in graph.weighted_edges() if not edge.kind.startswith("guarded_image_"))

    def debts(normalized):
        memory = normalized.memory_graph
        return tuple(normalized.dependencies.node(node).key for node in
                     (*memory.unresolved_read_nodes, *memory.unresolved_write_nodes, *normalized.may_alias_nodes))

    assert old_edges(before) == old_edges(after)
    assert debts(before) == debts(after)
    left, right = (summarize_function(item, unit.observation) for item in (before, after))
    # The new alternatives are not numerically consumed by the original
    # function summary. Its old facts and their own premise uses stay exact.
    assert left == right and left.premise_uses == right.premise_uses


def test_solver_budget_does_not_depend_on_host_speed(monkeypatch):
    """The per-function solver budget counts queries and z3 resource units only: slow checks (a loaded host) get
    the same answers (before: a 0.5 s wall-clock budget refused later queries, a load-dependent result)."""
    import time

    from tdo_v2 import _guarded_image_reads

    class Slow:
        def __init__(self):
            self.params = []

        def set(self, **params):
            self.params.append(params)

        def check(self):
            time.sleep(0.2)
            return "sat"

    budget, solver = _guarded_image_reads._Budget(), Slow()
    assert [budget.check(solver) for _ in range(5)] == ["sat"] * 5
    assert all(set(params) == {"rlimit", "random_seed"} for params in solver.params)   # no time-out
    budget.queries = budget.QUERIES
    with pytest.raises(_guarded_image_reads._Refused):
        budget.check(solver)


def test_expression_shape_is_limited_before_solving():
    """Symbolic-by-symbolic products are refused before any check (z3 accounts them sparsely: seconds within
    rlimit -- Astra review); scaled indexes and plain comparisons stay admitted."""
    import z3

    from tdo_v2 import _guarded_image_reads

    x, base = z3.BitVec("x", 64), z3.BitVecVal(0x1000, 64)
    admit = _guarded_image_reads._admissible
    assert admit(z3, z3.ULT(x, 8) == True, base + x * 8) is not None
    assert admit(z3, z3.ULT(x, 8) == True, base + x * (z3.BitVecVal(4, 64) | 0)) is not None   # folded constant
    chain = x
    for i in range(16):
        chain = chain * (x + i + 1)
    assert admit(z3, chain == 123456789, base + x) is None
    assert admit(z3, x * x == 4, base) is None
    # products by dense constants: refused once the weighted cost passes the cap (Astra's xorshift-multiply)
    import random

    rng, wide, mixed = random.Random(123), z3.BitVec("w", 256), None
    mixed = wide
    for _ in range(16):
        mixed = (mixed ^ z3.LShR(mixed, 13)) * rng.getrandbits(64)
    assert admit(z3, mixed == 123456789, base) is None
    # the node cap: a wide balanced sum of distinct leaves
    leaves = [z3.BitVec(f"v{i}", 8) for i in range(5000)]
    assert admit(z3, z3.Sum(leaves) == 0, base) is None
