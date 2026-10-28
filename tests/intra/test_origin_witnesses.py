"""Origin witnesses (``tdo_v2.origin_witnesses``, docs 25.19): why a root
reports a label -- per (writer, reader) may-alias transfer of the writer's
STORED value, with the address-difference window when both addresses are
exact; the values from before a call that may have changed them."""

from types import SimpleNamespace

from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, FunctionBuilder, add, const, copy, load, op, program_units, reg,
    store, straight, tmp,
)
from test_lane_slice import _seed_register
from tdo_v2.boundary import BoundaryKind
from tdo_v2.interprocedural import analyze_units
from tdo_v2.lane_slice import lane_index
from tdo_v2.origin_witnesses import root_witnesses

T = tmp(0x100)


def _witnesses(builder, sources, root):
    """``sources``: label -> (opcode, register, size) of its defining op;
    ``root``: (opcode, register, size) of the root definition."""
    (unit,) = program_units(builder)
    results = analyze_units([unit])
    normalized = results["1:1000"].normalized
    rows = []
    for label, (opcode, register, size) in sources.items():
        node, span = _seed_register(normalized, unit, opcode, register, size)
        rows.append(SimpleNamespace(kind=BoundaryKind.SOURCE, label=label, node=node, physical_spans=(span,),
                                    occurrence_ordinal=0))
    node, span = _seed_register(normalized, unit, *root)
    return root_witnesses(normalized, unit, rows, [(node, (span,))], set(sources), lane_index(normalized, unit),
                          results["1:1000"].origins)


def _three_pointers(*between_loads):
    """p1 = [rsi], p2 = [rdx], p3 = [rcx]; eax = A (edi), ebx = B (esi);
    [p1+0x30] = eax; [p2+0x34] = ebx; r9d = [p3+0x30]."""
    rows = [[load(reg(R8), reg(RSI))], *between_loads,
            [load(reg(R9), reg(RDX))],
            [load(reg(RCX), reg(RCX))],
            [copy(reg(RAX, 4), reg(RDI, 4))],
            [copy(reg(RBX, 4), reg(RSI, 4))],
            [add(T, reg(R8), const(0x30)), store(T, reg(RAX, 4))],
            [add(T, reg(R9), const(0x34)), store(T, reg(RBX, 4))],
            [add(T, reg(RCX), const(0x30)), load(reg(R9, 4), T)]]
    return straight(*rows)


SOURCES = {"A": ("COPY", RAX, 4), "B": ("COPY", RBX, 4)}
ROOT = ("LOAD", R9, 4)


def _may_alias(item):
    return [witness for witness in item["witnesses"] if witness["kind"] == "may_alias"]


def test_each_transfer_gets_its_own_window():
    found = _witnesses(_three_pointers(), SOURCES, ROOT)["origin_witnesses"]
    (a,), (b,) = _may_alias(found["A"]), _may_alias(found["B"])
    assert not found["A"]["has_debt_free_path"] and not found["B"]["has_debt_free_path"]
    assert "in [-3, 3]" in a["condition"] and "exclude" not in a["condition"]
    assert "in [-7, -1]" in b["condition"] and "equal pointers exclude this transfer" in b["condition"]
    assert a["writer"] != b["writer"] and a["reader"] == b["reader"]


def test_an_uncertain_address_writer_gets_no_window():
    # a store through an unrelated pointer before p2 is read: p2's load may
    # read it, so the B store's address is uncertain
    found = _witnesses(_three_pointers([store(reg(RDI), reg(RAX))]), SOURCES, ROOT)["origin_witnesses"]
    witnesses = _may_alias(found["B"])
    assert witnesses and all(item["condition"] is None for item in witnesses)
    assert any(item["reason"] == "uncertain-address writer" for item in witnesses)


def test_a_label_only_in_a_writer_address_is_not_its_stored_value():
    # B (esi) only moves the A store's address: a[ebx] = eax
    builder = straight(
        [load(reg(R8), reg(RSI))],
        [load(reg(RCX), reg(RCX))],
        [copy(reg(RAX, 4), reg(RDI, 4))],
        [copy(reg(RBX, 4), reg(RSI, 4))],
        [op("INT_ZEXT", [reg(RBX, 4)], reg(RBX)), add(T, reg(R8), reg(RBX)), store(T, reg(RAX, 4))],
        [add(T, reg(RCX), const(0x30)), load(reg(R9, 4), T)],
    )
    found = _witnesses(builder, SOURCES, ROOT)["origin_witnesses"]
    assert _may_alias(found["A"])
    assert not _may_alias(found.get("B", {"witnesses": []}))


def test_a_value_from_before_a_call_names_the_call():
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), reg(RDI)))
               .call(CODE_BASE + 0x900)
               .ins(copy(reg(RCX), reg(RAX)))
               .add_rsp(0x28).ret())
    found = _witnesses(builder, {"A": ("COPY", RAX, 8)}, ("COPY", RCX, 8))["origin_witnesses"]
    (witness,) = [item for item in found["A"]["witnesses"] if item["kind"] == "call_clobber"]
    assert "if they leave it unchanged" in witness["condition"] and "CALL" in witness["condition"]
    assert not found["A"]["has_debt_free_path"]


def test_only_the_stored_bytes_of_a_wider_value_are_its_stored_value():
    # rdx = PIECE(ebx = B, eax = A); [p1+0x30] = edx -- only A is stored
    builder = straight(
        [load(reg(R8), reg(RSI))],
        [load(reg(RCX), reg(RCX))],
        [copy(reg(RAX, 4), reg(RDI, 4))],
        [copy(reg(RBX, 4), reg(RSI, 4))],
        [op("PIECE", [reg(RBX, 4), reg(RAX, 4)], reg(RDX))],
        [add(T, reg(R8), const(0x30)), store(T, reg(RDX, 4))],
        [add(T, reg(RCX), const(0x30)), load(reg(R9, 4), T)],
    )
    found = _witnesses(builder, SOURCES, ROOT)["origin_witnesses"]
    assert _may_alias(found["A"])
    assert not _may_alias(found["B"])


def _after_an_opaque_call():
    return (FunctionBuilder().sub_rsp(0x28)
            .ins(copy(reg(RAX), reg(RDI)))
            .call(CODE_BASE + 0x900)
            .ins(copy(reg(RCX), reg(RAX)))
            .add_rsp(0x28).ret())


def test_a_label_on_the_call_clobber_debt_is_a_value_the_call_produced():
    (unit,) = program_units(_after_an_opaque_call())
    results = analyze_units([unit])
    normalized = results["1:1000"].normalized
    (debt,) = [node for nodes, row in zip(normalized.call_clobber_debts, normalized.call_clobber_reads)
               if row.operation_key.endswith(":COPY") for node in nodes]
    rows = [SimpleNamespace(kind=BoundaryKind.SOURCE, label="S", node=debt, physical_spans=(), occurrence_ordinal=0)]
    node, span = _seed_register(normalized, unit, "COPY", RCX, 8)
    found = root_witnesses(normalized, unit, rows, [(node, (span,))], {"S"}, lane_index(normalized, unit),
                           results["1:1000"].origins)["origin_witnesses"]
    assert [item["kind"] for item in found["S"]["witnesses"]] == ["call_value"]
    assert not found["S"]["has_debt_free_path"]


def test_bytes_overwritten_before_the_store_are_not_its_stored_value():
    # rdx = PIECE(ebx = B, eax = A); high32(rdx) = 0; [p1+0x30] = rdx: B's
    # bytes no longer reach the stored value
    builder = straight(
        [load(reg(R8), reg(RSI))],
        [load(reg(RCX), reg(RCX))],
        [copy(reg(RAX, 4), reg(RDI, 4))],
        [copy(reg(RBX, 4), reg(RSI, 4))],
        [op("PIECE", [reg(RBX, 4), reg(RAX, 4)], reg(RDX))],
        [copy(reg(RDX + 4, 4), const(0, 4))],
        [add(T, reg(R8), const(0x30)), store(T, reg(RDX))],
        [add(T, reg(RCX), const(0x30)), load(reg(R9, 4), T)],
    )
    found = _witnesses(builder, SOURCES, ROOT)["origin_witnesses"]
    assert _may_alias(found["A"])
    assert not _may_alias(found["B"])


def test_distinct_pointers_print_differently():
    found = _witnesses(_three_pointers(), SOURCES, ROOT)["origin_witnesses"]
    (b,) = _may_alias(found["B"])
    left, right = b["condition"].split(" in [")[0].split("] - [")
    assert left.strip("[]") != right.strip("[]")


def test_switched_off_lane_origins_are_reported_as_a_node_fallback(monkeypatch):
    from tdo_v2.summary_engine import _witnesses as engine_witnesses

    monkeypatch.setenv("TDO_V2_LANE_ORIGINS", "0")
    (unit,) = program_units(_after_an_opaque_call())
    results = analyze_units([unit])
    normalized = results["1:1000"].normalized
    source, source_span = _seed_register(normalized, unit, "COPY", RAX, 8)
    root, root_span = _seed_register(normalized, unit, "COPY", RCX, 8)
    rows = [SimpleNamespace(kind=BoundaryKind.SOURCE, label="A", node=source, physical_spans=(source_span,),
                            occurrence_ordinal=0),
            SimpleNamespace(kind=BoundaryKind.SINK, label="sink", node=root, physical_spans=(root_span,),
                            occurrence_ordinal=0)]
    found = engine_witnesses(SimpleNamespace(normalized=normalized), unit, rows, "sink", 0, {"A"}, {"A"}, {},
                             results["1:1000"].origins)
    assert found["origin_witnesses"]["A"]["traversal"] == "node-fallback"
