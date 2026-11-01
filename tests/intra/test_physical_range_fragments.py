"""Physical byte queries compose current original SSA, not stale wide values."""

from collections import Counter

import pytest

from synthetic import (
    Arch, CONST, DATA_BASE, RAM, REG, R8, RAX, RCX, RDX, RSP, ZF,
    X64, X86_32, FunctionBuilder, add, const, copy, op, program_units, reg, store, tmp,
)
from test_state_barrier import OPAQUE, SINK, _keys, _view
from tdo_v2.integration.configured_boundary_demands import _canonical_boundary_nodes, _direct_sink_boundary_nodes
from tdo_v2.integration.configured_physical_state import _FunctionPhysicalStateBackend
from tdo_v2.physical_state import PhysicalMemorySlice, PhysicalRegisterSlice


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)


def _memory_case(route, rows=((8, 4, RCX), (12, 8, R8)), *, barrier=None, base=DATA_BASE, big=False):
    body = FunctionBuilder().sub_rsp(0x60)
    if big:
        body.arch = Arch("x86:BE:64:default", 8, RSP, 0x288)

    def address():
        body.ins(copy(reg(RDX), const(base))) if route == "relational" else \
            body.ins(add(reg(RDX), reg(RSP), const(0x20)))

    address()
    writers = []
    for ordinal, (offset, width, source) in enumerate(rows):
        if barrier == "branch" and ordinal == len(rows) - 1:
            body.cbranch("consume", reg(ZF, 1))
        value, pointer = tmp(0x9000 + ordinal * 0x20, width), tmp(0x8800)
        body.ins(copy(value, reg(source, width)))
        key = f"1:{body.entry + len(body._rows) * body.stride:x}:1:STORE"
        body.ins(add(pointer, reg(RDX), const(offset)), store(pointer, value))
        writers.append(key)
    if barrier in ("call", "callother"):
        body.call(OPAQUE) if barrier == "call" else body.ins(op("CALLOTHER", [const(0x77, 4)]))
        address()  # Restore the address: memory preservation must still be proved.
    elif barrier == "alias":
        body.ins(store(reg(RAX), const(0x77, 1)))
    elif barrier == "wrap-alias":
        pointer = tmp(0x9900)
        body.ins(add(pointer, reg(RDX), const((1 << 63) - 1)),
                 add(pointer, pointer, const((1 << 63) - 1)), add(pointer, pointer, const(10)))
        writers.append(f"1:{body.entry + len(body._rows) * body.stride:x}:0:STORE")
        body.ins(store(pointer, const(0xee, 1)))
    elif barrier == "seam-alias":
        pointer, value = tmp(0x9900), tmp(0x9910, 16)
        body.ins(add(pointer, reg(RDX), const((1 << 64) - 4)), copy(value, reg(R8, 16)))
        writers.append(f"1:{body.entry + len(body._rows) * body.stride:x}:0:STORE")
        body.ins(store(pointer, value))
    body.label("consume").call(SINK).add_rsp(0x60).ret()
    view = _view(body)
    key = _keys(view, "CALL")[-1]
    return view, key, tuple(writers)


def _fragments(view, key, offset, size):
    backend = _FunctionPhysicalStateBackend(view)
    selector = PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), offset, size)
    return selector, backend.value_fragments(selector, view.position(key))


def _byte_writers(view, key, selector, fragments):
    """Retain each requested memory byte and its byte within the raw STORE."""
    backend, found = _FunctionPhysicalStateBackend(view), {}
    candidates = backend.memory_candidates(selector, view.position(key))
    base_span = backend.register_span(selector.base)
    base_id = view.state_definition(base_span, view.position(key))
    relation = view.canonical_physical_affine_relation(base_id, base_span, 0)
    for fragment in fragments:
        definition = view.memory.definitions[fragment.definition_id]
        assert definition.span.contains(fragment.source_span)
        receipt = fragment.store_receipt
        if receipt is None:
            assert len(candidates) == 1 and definition.operation_key is not None
            at = selector.displacement + fragment.source_span.start - candidates[0].start
            value_offset = fragment.source_span.start - definition.span.start
            writer = definition.operation_key
        else:
            assert receipt.consuming_operation == key and receipt.before_position == view.position(key)
            assert receipt.source_span == fragment.source_span
            assert receipt.byte_size == fragment.source_span.size
            at = receipt.target_offset - relation[2]
            value_offset = receipt.target_offset - receipt.store_offset
            writer = receipt.store_operation
        for byte in range(fragment.source_span.size):
            assert at + byte not in found
            found[at + byte] = writer, value_offset + byte
    assert set(found) == set(range(selector.displacement, selector.displacement + selector.byte_size))
    return found


def _concrete_writers(view, route, offset, size, *, base=DATA_BASE):
    from pcode_interpreter import Interpreter

    sink, = program_units(FunctionBuilder(entry=SINK).ret())
    vm = Interpreter(view.observation, constant_space=CONST, seed=0, address_bits={RAM: 64},
                     program={(RAM, SINK): sink.observation})
    stack = 0x70000000
    vm.preset(REG, RSP, 8, stack)
    vm.preset(REG, RCX, 8, 0x0123456789abcdef)
    vm.preset(REG, R8, 8, 0xfedcba9876543210)
    run = vm.run()
    assert run.completed and not vm.opaque_opcodes
    # The original RET-only sink and the remaining epilogue never write this
    # buffer. Its final byte writers are therefore its writers at the query.
    physical = base if route == "relational" else stack - 0x60 + 0x20
    return {byte: vm._bytes[RAM, (physical + byte) % (1 << 64)][1]
            for byte in range(offset, offset + size)}


@pytest.mark.parametrize("route", ("materialized", "relational"))
@pytest.mark.parametrize("offset,size", ((8, 12), (10, 6), (11, 2)))
def test_adjacent_original_stores_answer_one_arbitrary_range_without_widening_ids(route, offset, size):
    view, key, (low, high) = _memory_case(route)
    original, edges = view.memory, Counter(view.normalized.dependencies.weighted_edges())
    selector, fragments = _fragments(view, key, offset, size)
    assert len(fragments) == 2
    expected = {byte: (low, byte - 8) if byte < 12 else (high, byte - 12)
                for byte in range(offset, offset + size)}
    assert _byte_writers(view, key, selector, fragments) == expected
    assert _concrete_writers(view, route, offset, size) == {byte: writer for byte, (writer, _) in expected.items()}
    assert _FunctionPhysicalStateBackend(view).value_ids(selector, view.position(key)) == ()
    assert view.memory is original and Counter(view.normalized.dependencies.weighted_edges()) == edges


@pytest.mark.parametrize("route", ("materialized", "relational"))
def test_partial_overwrite_keeps_both_noncontiguous_slices_of_the_old_definition(route):
    view, key, (wide, patch) = _memory_case(route, ((8, 16, RCX), (14, 4, R8)))
    selector, fragments = _fragments(view, key, 10, 10)
    assert len(fragments) == 3
    assert _byte_writers(view, key, selector, fragments) == {
        byte: (patch, byte - 14) if 14 <= byte < 18 else (wide, byte - 8) for byte in range(10, 20)}
    assert _concrete_writers(view, route, 10, 10) == {
        byte: patch if 14 <= byte < 18 else wide for byte in range(10, 20)}
    first, _, last = fragments
    assert first.definition_id == last.definition_id
    assert not first.source_span.overlaps(last.source_span)
    assert first.source_span.start > view.memory.definitions[first.definition_id].span.start


@pytest.mark.parametrize("route", ("materialized", "relational"))
def test_one_missing_byte_refuses_the_whole_range_not_a_complete_subset(route):
    view, key, _ = _memory_case(route, ((8, 4, RCX), (13, 8, R8)))
    assert not _fragments(view, key, 8, 13)[1]
    assert _fragments(view, key, 8, 4)[1] and _fragments(view, key, 13, 8)[1]


@pytest.mark.parametrize("route", ("materialized", "relational"))
@pytest.mark.parametrize("barrier", ("call", "callother", "alias", "branch"))
def test_any_unproved_piece_or_intervening_effect_keeps_the_range_unbound(route, barrier):
    view, key, _ = _memory_case(route, barrier=barrier)
    original, debts = view.memory, (view.normalized.may_alias_reads, view.normalized.call_clobber_reads)
    assert not _fragments(view, key, 8, 12)[1]
    assert view.memory is original
    assert (view.normalized.may_alias_reads, view.normalized.call_clobber_reads) == debts


def test_register_fragments_and_canonical_roots_keep_disjoint_source_byte_selections():
    from tdo_v2.lane_slice import lane_slice, reached_bytes

    body = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RDX)))
            .ins(copy(reg(RCX + 2, 2), reg(R8, 2))).call(SINK).add_rsp(0x28).ret())
    view = _view(body)
    key = _keys(view, "CALL")[-1]
    selector = PhysicalRegisterSlice(RCX, 8)
    backend = _FunctionPhysicalStateBackend(view)
    fragments = backend.value_fragments(selector, view.position(key))
    assert [(f.source_span.start, f.source_span.size) for f in fragments] == [(RCX, 2), (RCX + 2, 2), (RCX + 4, 4)]
    assert fragments[0].definition_id == fragments[2].definition_id
    assert backend.value_ids(selector, view.position(key)) == ()
    rows = _direct_sink_boundary_nodes(view, "bytes", key, view.position(key), 0, (selector,))
    canonical = _canonical_boundary_nodes(list(rows))
    assert len(canonical) == 2
    original = next(row for row in canonical if len(row.physical_spans) == 2)
    assert original.physical_spans == (fragments[0].source_span, fragments[2].source_span)
    lane = lane_slice(view.normalized, view.analysis.evidence.unit,
                      [(row.node, row.physical_spans) for row in canonical])
    inputs = reached_bytes(lane, view.normalized)
    assert {RDX, RDX + 1, *range(RDX + 4, RDX + 8), R8, R8 + 1} <= inputs
    assert not {RDX + 2, RDX + 3, R8 + 2, R8 + 3} & inputs


@pytest.mark.parametrize("route", ("materialized", "relational"))
def test_overlapping_selectors_cannot_duplicate_a_physical_consumption(route):
    view, key, _ = _memory_case(route)
    selector, fragments = _fragments(view, key, 8, 12)
    assert fragments
    assert not _direct_sink_boundary_nodes(view, "bytes", key, view.position(key), 0, (selector, selector))


def test_duplicate_source_bytes_are_refused_without_picking_one_target_receipt():
    value, pointer = tmp(0x9100, 4), tmp(0x9200)
    body = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RDX), const(DATA_BASE)))
            .ins(copy(value, reg(RCX, 4))))
    for offset in (8, 12):
        body.ins(add(pointer, reg(RDX), const(offset)), store(pointer, value))
    body.call(SINK).add_rsp(0x28).ret()
    view = _view(body)
    key = _keys(view, "CALL")[-1]
    first, = _fragments(view, key, 8, 4)[1]
    second, = _fragments(view, key, 12, 4)[1]
    assert first.definition_id == second.definition_id and first.source_span == second.source_span
    assert (first.store_receipt.target_offset, second.store_receipt.target_offset) == (8, 12)
    assert first.store_receipt.store_operation != second.store_receipt.store_operation
    # The current fragment contract deliberately refuses this non-bijective
    # source-byte selection; it must not silently choose one target receipt.
    assert not _fragments(view, key, 8, 8)[1]


def test_big_endian_whole_stores_do_not_authorize_little_endian_source_subranges():
    view, key, (low, high) = _memory_case("relational", big=True)
    selector, fragments = _fragments(view, key, 8, 12)
    assert _byte_writers(view, key, selector, fragments) == {
        byte: (low, byte - 8) if byte < 12 else (high, byte - 12) for byte in range(8, 20)}
    assert not _fragments(view, key, 10, 6)[1]


def test_modular_address_boundary_never_revives_overwritten_bytes():
    view, key, (wide, patch) = _memory_case("relational", ((8, 8, RCX), (12, 4, R8)), base=(1 << 64) - 12)
    selector, fragments = _fragments(view, key, 8, 8)
    # This stage may refuse a wrapping address; if it binds, every byte must
    # retain the actual last STORE rather than the old wide containing value.
    if fragments:
        assert _byte_writers(view, key, selector, fragments) == {
            byte: (wide, byte - 8) if byte < 12 else (patch, byte - 12) for byte in range(8, 16)}
        assert _concrete_writers(view, "relational", 8, 8, base=(1 << 64) - 12) == {
            byte: wide if byte < 12 else patch for byte in range(8, 16)}


@pytest.mark.parametrize("route", ("materialized", "relational"))
@pytest.mark.parametrize("size", (4, 12))
def test_wrapped_affine_alias_cannot_hide_the_actual_later_one_byte_overwrite(route, size):
    view, key, (low, high, wrapped) = _memory_case(route, barrier="wrap-alias")
    selector, fragments = _fragments(view, key, 8, size)
    actual = _concrete_writers(view, route, 8, size)
    # Three original 64-bit ADDs yield base+8, not a disjoint base+2**64+8.
    assert actual == {byte: wrapped if byte == 8 else low if byte < 12 else high
                      for byte in range(8, 8 + size)}
    if fragments:
        claimed = _byte_writers(view, key, selector, fragments)
        assert {byte: writer for byte, (writer, _) in claimed.items()} == actual
        assert claimed[8] == (wrapped, 0)


@pytest.mark.parametrize("offset,size", (((1 << 64) - 4, 8), (0, 4)))
def test_unsigned_seam_crossing_request_or_candidate_requires_a_split_proof(offset, size):
    view, key, (writer,) = _memory_case("relational", (((1 << 64) - 4, 8, RCX),))
    assert _concrete_writers(view, "relational", offset, size) == {
        byte: writer for byte in range(offset, offset + size)}
    # The first query itself crosses the unsigned affine modulus seam; the
    # second is covered by a crossing STORE. Neither gets a linear receipt.
    assert not _fragments(view, key, offset, size)[1]


@pytest.mark.parametrize("size", (4, 12))
def test_intervening_seam_crossing_store_is_a_barrier_not_an_ignored_candidate(size):
    clean, clean_key, _ = _memory_case("relational")
    assert _fragments(clean, clean_key, 8, size)[1]
    view, key, (_, high, crossing) = _memory_case("relational", barrier="seam-alias")
    # The raw wrapped STORE is [base-4, base+12): it overwrites the entire
    # first four bytes, even though its canonical unsigned interval crosses 0.
    assert _concrete_writers(view, "relational", 8, size) == {
        byte: crossing if byte < 12 else high for byte in range(8, 8 + size)}
    assert not _fragments(view, key, 8, size)[1]


@pytest.mark.parametrize("arch,pointer_width", ((X64, 8), (X64, 4), (X86_32, 4), (X86_32, 8)))
def test_relational_address_space_and_actual_pointer_width_must_match(arch, pointer_width):
    body = FunctionBuilder(arch=arch).sub_rsp(0x28)
    base, pointer, value = reg(0x80, pointer_width), tmp(0x8800, pointer_width), tmp(0x9900, 4)
    body.ins(copy(base, const(DATA_BASE, pointer_width)), copy(value, reg(RAX, 4)))
    body.ins(add(pointer, base, const(8, pointer_width)), store(pointer, value))
    body.call(SINK).add_rsp(0x28).ret()
    view = _view(body)
    key = _keys(view, "CALL")[-1]
    selector = PhysicalMemorySlice(PhysicalRegisterSlice(0x80, pointer_width), 8, 4)
    backend = _FunctionPhysicalStateBackend(view)
    assert not backend.memory_candidates(selector, view.position(key))
    found = backend.value_fragments(selector, view.position(key))
    assert bool(found) is (arch.address_bits == pointer_width * 8)
    if found:
        fragment, = found
        assert fragment.source_span.size == fragment.store_receipt.byte_size == 4


@pytest.mark.parametrize("route", ("materialized", "relational"))
def test_fragment_cap_refuses_a_range_instead_of_returning_its_first_128_pieces(route):
    from tdo_v2.integration.configured_physical_state import MAX_PHYSICAL_VALUE_FRAGMENTS

    assert MAX_PHYSICAL_VALUE_FRAGMENTS == 128
    view, key, writers = _memory_case(route, tuple((i, 1, RCX) for i in range(129)))
    assert not _fragments(view, key, 0, 129)[1]
    selector, fragments = _fragments(view, key, 0, 128)
    assert len(fragments) == 128
    assert _byte_writers(view, key, selector, fragments) == {i: (writers[i], 0) for i in range(128)}
