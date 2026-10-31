"""Bitwise indices retain real memory SSA edges, not merely equal ranges."""

import pytest

from graph_oracle import check
from synthetic import (
    AARCH64, X64, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder,
    add, const, load, op, program_units, reg, store, tmp,
)
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


def _fixture(arch=X64, *, change=None):
    builder, keys = FunctionBuilder(arch=arch), {}
    manager, pointer, index, address, flag = (tmp(0x100), tmp(0x200), tmp(0x300),
                                              tmp(0x400), tmp(0x500, 1))

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations)-1}:{operations[-1][0]}"
        builder.ins(*operations)

    ins("manager", add(manager, reg(RDI), const(32)), load(manager, manager))
    ins("buffer", load(pointer, manager))
    ins("index", op("INT_AND", [reg(RSI), const(0xff)], index),
        op("INT_RIGHT", [index, const(4, 4)], index))
    builder.cbranch("done", flag, op("INT_LESS", [const(7), index], flag))
    ins("store", op("INT_LEFT", [index, const(2, 4)], address),
        add(address, pointer, address), store(address, reg(RDX, 4)))
    if change == "index":
        builder.ins(add(index, index, const(1)), op("INT_LEFT", [index, const(2, 4)], address),
                    add(address, pointer, address))
    elif change == "pointer-slot":
        builder.ins(store(manager, reg(RBX)), load(pointer, manager),
                    op("INT_LEFT", [index, const(2, 4)], address), add(address, pointer, address))
    elif change == "partial-pointer":
        builder.ins(store(manager, reg(RBX, 1)), load(pointer, manager),
                    op("INT_LEFT", [index, const(2, 4)], address), add(address, pointer, address))
    elif change == "call":
        builder.call(0x1f00)
    ins("read", load(reg(RAX, 4), address))
    builder.label("done").ret()
    return builder, keys


def _normalize(builder):
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit.observation


def _writes(normalized, key):
    ssa = normalized.memory_ssa
    return [ssa.definitions[d] for action in ssa.actions if action.operation_key == key
            for d in action.write_definition_ids]


def _memory_read(normalized, key):
    ssa = normalized.memory_ssa
    return [read for read in ssa.reads if ssa.actions[read.action_id].operation_key == key
            and read.span.object_id.kind.value in ("address_space", "function_relative")]


def _image(space, address):
    for start, value in ((0x50000020, 0x50001000), (0x50001000, 0x50002000)):
        if start <= address < start + 8:
            return (value >> (8 * (address - start))) & 0xff
    return None


@pytest.mark.parametrize("arch", (X64, AARCH64))
@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_two_loads_masked_shifted_index_guard_and_target_definition(monkeypatch, arch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    body, keys = _fixture(arch)
    normalized, observation = _normalize(body)
    (written,) = _writes(normalized, keys["store"])
    (read,) = _memory_read(normalized, keys["read"])
    assert written.span == read.span and written.span.size == 4
    assert written.kind is MemoryDefinitionKind.DATA_WRITE
    assert written.span.object_id in normalized.wild_objects
    identifier = normalized.memory_ssa.definitions.index(written)
    assert read.fragments[0].definition_ids == (identifier,)
    graph = normalized.dependencies
    target = normalized.memory_graph.definition_nodes[identifier]
    assert any(t == target and edge.kind == "memory_defines"
               for _, t, edge in graph.out_edges(graph.node_for_key("op:" + keys["store"])))
    assert any(s == target and edge.kind == "memory_read" and edge.span == read.span
               for s, _, edge in graph.in_edges(graph.node_for_key("op:" + keys["read"])))
    # The pointer expressions do not replace the original LOAD/bit/guard nodes.
    assert all(graph.node_for_key("op:" + key) is not None for key in keys.values())
    report = check(normalized, observation, seeds=range(12), image=_image,
                   register_pools=lambda seed: {RSP: 0x70000000, RDI: 0x50000000,
                                                RSI: seed * 19, RDX: 0x12345678 + seed})
    assert report.runs == 12 and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("change", ("index", "pointer-slot", "partial-pointer", "call"))
def test_changed_inputs_never_reuse_the_old_store_as_the_only_writer(change):
    body, keys = _fixture(change=change)
    normalized, _ = _normalize(body)
    writes = _writes(normalized, keys["store"])
    assert writes
    reads = _memory_read(normalized, keys["read"])
    identifier = normalized.memory_ssa.definitions.index(writes[0])
    assert not reads or any(read.span != writes[0].span or
                           read.fragments[0].definition_ids != (identifier,)
                           for read in reads) or normalized.call_clobber_reads


def test_index_switch_keeps_nonconstant_bitwise_addresses_unresolved(monkeypatch):
    monkeypatch.setenv("TDO_V2_INDEX_ADDRESSES", "0")
    body, keys = _fixture()
    normalized, _ = _normalize(body)
    assert not _writes(normalized, keys["store"])
    assert any(normalized.memory_ssa.actions[row.action_id].operation_key == keys["store"]
               for row in normalized.memory_ssa.unresolved_writes)
