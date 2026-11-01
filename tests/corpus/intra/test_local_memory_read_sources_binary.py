"""Original ncnn local overwrite and zlib's real intervening-byte barrier.

Reuse the sealed image/observation/producer pins and source keys, without
changing raw p-code or claiming entry-to-window reachability of the parser.
"""

import pytest

from test_external_memory_value_paths_binary import CASES, PRODUCERS, external_units
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


@pytest.fixture(scope="module", params=("sparse", "dense"))
def cases(external_units, request):
    with pytest.MonkeyPatch.context() as setting:
        setting.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
        setting.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
        result = {entry: FunctionNormalizer().normalize(external_units[entry]) for entry in (0x548970, 0x107360)}
    assert all(isinstance(normalized, NormalizedFunction) for normalized in result.values())
    return result


def _seeds(normalized, reader):
    return [(normalized.memory_graph.definition_nodes[index], (definition.span,))
            for index, definition in enumerate(normalized.memory_ssa.definitions) if definition.operation_key == reader]


def test_ncnn_original_eight_byte_store_has_a_consumed_local_source(external_units, cases):
    from tdo_v2._memory_read_sources import read_source
    from tdo_v2.lane_slice import lane_slice

    normalized, unit = cases[0x548970], external_units[0x548970]
    writer, reader, width, _ = CASES[0x548970]
    local = normalized.memory_graph.local_reads
    assert local is not None
    row, = [row for row in local.plan.reads if row.reader == reader]
    assert row.writer == writer and row.output_span.size == width == 8
    part, = row.parts
    assert (part.value_offset, part.output_offset, part.width, part.constant) == (0, 0, 8, None)
    definition = normalized.memory_ssa.definitions[part.source_definition_id]
    assert definition.operation_key == PRODUCERS[0x548970] and definition.span.contains(part.source_span)
    assert part.source_span.start == 0x4040 and part.source_span.size == 8
    assert row.corridor == ("1b1:548c7c:0:COPY",)
    first, second, span, corridor = row.address_ports[0]
    assert len(row.address_ports) == 1
    assert (first, second, corridor) == ("1b1:548c78:0:COPY", "1b1:548c7c:0:COPY", (writer,))
    assert span.object_id.kind.value == "register_file" and (span.start, span.size) == (0x4098, 8)
    graph = normalized.dependencies
    old_memory_debts = {node for claim, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes)
                        if claim.operation_key == reader}
    assert old_memory_debts  # The original 56-writer diagnostic is retained.
    assert sum(len(claim.writers) for claim in normalized.may_alias_reads if claim.operation_key == reader) == 56
    view = read_source(normalized, reader)
    assert view.local == row and old_memory_debts <= set(view.inactive_debts)
    lane = lane_slice(normalized, unit, _seeds(normalized, reader))
    assert not (old_memory_debts & lane.nodes)
    address_debts = {source for source, _, edge in graph.in_edges(graph.node_for_key("op:" + second))
                     if edge.kind == "call_clobber_read"}
    assert address_debts and not (address_debts & set(view.inactive_debts))
    assert address_debts <= lane.nodes
    source = normalized.memory_graph.definition_nodes[part.source_definition_id]
    assert source in lane.nodes and graph.node_for_key("op:" + PRODUCERS[0x548970]) in lane.nodes
    assert normalized.may_alias_reads and normalized.call_clobber_reads


def test_zlib_intervening_one_byte_store_remains_a_live_memory_alternative(external_units, cases):
    from tdo_v2._memory_read_sources import read_source
    from tdo_v2.lane_slice import lane_slice

    normalized, unit = cases[0x107360], external_units[0x107360]
    writer, reader, width, alias = CASES[0x107360]
    assert width == 8 and alias is not None
    local = normalized.memory_graph.local_reads
    assert local is None or not any(row.reader == reader for row in local.plan.reads)
    assert read_source(normalized, reader) is None
    claim, debt = next((claim, node) for claim, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes)
                       if claim.operation_key == reader and alias in claim.writers)
    assert claim.writers == (alias,)
    lane = lane_slice(normalized, unit, _seeds(normalized, reader))
    assert debt in lane.nodes and normalized.dependencies.node_for_key("op:" + alias) in lane.nodes
    assert normalized.dependencies.node_for_key("op:" + writer) in lane.nodes


@pytest.fixture(scope="module", params=("sparse", "dense"))
def byte_selected_suite09(request):
    import os
    from pathlib import Path

    from test_forward_call_value_ports_binary import GENERATION, IMAGE_SHA, NAMING_SHA
    from tdo_v2.configured_naming_contracts import NamingBindingExpectation
    from tdo_v2.image_info import load_image_info
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.observed_function_session import open_observed_function_session
    from tdo_v2.interprocedural import analyze_units, function_key

    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to the original sealed Suite09 data")
    generation = Path(location) / "tdo_bundles3/v2-win-debug-full" / GENERATION
    pins = {
        "1b1:14000208e": "d0a4754767b554f940bbc0b76cc7516529b76de29ea55eb3f53d5e7167c1896f",
        "1b1:1400019d0": "7263cffceb0c4a4860e85c0c12818f40d2c352f23ff7c639e946dfd0ff2966f3",
        "1b1:1400019df": "033e262a3ef694c5c7aa7db09ba87e2691fa453499e030fdaed4b6243aa65087",
        "1b1:140001a27": "4b2fbad5fdff39b84dcdf0b1293d187b692845fd39154f35cd9aa036f18ef33e",
    }
    with open_observed_function_session(admit_frozen_bundle(generation),
            naming_binding=NamingBindingExpectation(bytes.fromhex(NAMING_SHA), "12.0.4")) as session:
        units = {function_key(row.unit.scopes.function.entry): row.unit for row in session.iter_functions()
                 if function_key(row.unit.scopes.function.entry) in pins}
    assert set(units) == set(pins)
    for key, unit in units.items():
        assert unit.scopes.function.observation_digest.hex() == pins[key]
        assert unit.scopes.program.evidence.executable_sha256.hex() == IMAGE_SHA
    info = load_image_info(generation)
    with pytest.MonkeyPatch.context() as settings:
        settings.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
        settings.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
        settings.setenv("TDO_V2_FORWARD", "1")
        results = analyze_units(tuple(units.values()), image_info=info)
    assert all(not item.declared and not item.test_only_inputs for item in results.values())
    return units, results["1b1:14000208e"], info


def test_original_partial_dword_patch_does_not_pollute_the_later_al_selection(byte_selected_suite09):
    from tdo_v2._memory_read_sources import read_source
    from tdo_v2.lane_slice import lane_slice
    from tdo_v2.model import ByteSpan

    units, item, _ = byte_selected_suite09
    n, unit = item.normalized, item.unit
    reader, patch = "1b1:1400020ad:1:LOAD", "1b1:1400020aa:2:STORE"
    row, = [row for row in n.memory_graph.local_reads.plan.reads if row.reader == reader]
    assert not row.complete and read_source(n, reader) is None
    part, = row.parts
    assert (part.writer, part.output_offset, part.value_offset, part.width) == (patch, 1, 0, 1)
    assert n.memory_ssa.definitions[part.source_definition_id].operation_key == "1b1:1400020aa:1:COPY"
    source_b = n.memory_graph.definition_nodes[part.source_definition_id]
    binding, graph = n.memory_graph.local_reads, n.dependencies
    index = sum(len(prior.parts) for prior in binding.plan.reads[:binding.plan.reads.index(row)])
    effect = binding.effect_nodes[index]
    assert any(source == source_b and edge.kind == "local_read_from_value"
               and edge.span == part.source_span and edge.occurrence == 0
               for source, _, edge in graph.in_edges(effect))
    output_byte = ByteSpan(row.output_span.object_id, row.output_span.start + 1, 1)
    assert any(target == graph.node_for_key("op:" + reader) and edge.kind == "local_read_from"
               and edge.span == output_byte and edge.occurrence == 1
               for _, target, edge in graph.out_edges(effect))
    assert any(source == graph.node_for_key("op:" + patch) and edge.kind == "local_read_from_witness"
               for source, _, edge in graph.in_edges(effect))
    source_a, = [n.memory_graph.definition_nodes[i] for i, d in enumerate(n.memory_ssa.definitions)
                 if d.operation_key == "1b1:1400020a2:1:COPY"]
    output, = _seeds(n, reader)
    for selected in ((0,), (1,), (0, 2), (0, 1), (3,), tuple(range(4))):
        node, (span,) = output
        lane = lane_slice(n, unit, ((node, tuple(ByteSpan(span.object_id, span.start + i, 1)
                                                   for i in selected)),))
        assert (source_a in lane.nodes) is (0 in selected)
        assert (source_b in lane.nodes) is (1 in selected)
    # The real consumer loads all four bytes, then keeps only AL before the
    # sink argument COPY. The disjoint byte-1 port must not reintroduce B.
    lane = lane_slice(n, unit, _seeds(n, "1b1:1400020b3:0:COPY"))
    assert source_a in lane.nodes and source_b not in lane.nodes
    ssa = n.memory_ssa
    memory_read, = [r for r in ssa.reads if ssa.actions[r.action_id].operation_key == reader
                   and r.span.object_id.kind.value == "function_relative"]
    assert memory_read.span.size == 4
    for fragment in memory_read.fragments:
        for identifier in fragment.definition_ids:
            assert any(source == n.memory_graph.definition_nodes[identifier]
                       and edge.kind == "memory_read" and edge.span == fragment.span
                       for source, _, edge in graph.in_edges(graph.node_for_key("op:" + reader)))


def test_original_al_selection_executes_both_stores_but_uses_only_the_low_source(byte_selected_suite09):
    from forward_oracle import _Recording

    units, item, info = byte_selected_suite09
    seed_global, = [row for row in info.exports if row.name == "g_dfb_source_seed"]
    program = {(u.scopes.function.entry.space_id, u.scopes.function.entry.byte_offset): u.observation
               for u in units.values()}
    reader = "1b1:1400020ad:1:LOAD"
    for i, seed in enumerate((0, 1, 0x7fffffff, 0xffffffff)):
        stack = 0x70000000 + 0x100 * i
        vm = _Recording(item.unit.observation, constant_space=48, seed=i, program=program,
                        subjects={"1b1:1400020b3:0:COPY": 0})
        vm.preset(548, 32, 8, stack)
        vm.preset(seed_global.space_id, seed_global.byte_offset, 4, seed)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        assert vm.seen == {"1b1:1400020b3:0:COPY": [(seed + 1) & 0xff]}
        assert {(d.offset - (stack - 12), d.writer) for d in run.dependencies
                if d.reader == reader and d.space_id == 433} == {
            (0, "1b1:1400020a2:2:STORE"), (1, "1b1:1400020aa:2:STORE"),
            (2, "1b1:140002096:2:STORE"), (3, "1b1:140002096:2:STORE")}
