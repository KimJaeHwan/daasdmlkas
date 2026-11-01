"""Caller allocation identity crosses verified pre-call physical value ports.

These are original SSA uses and real raw helper summaries, not allocation
wrapper births, an ABI return-register guess, or CALL-memory preservation.
The selected value relation and the object's lifetime remain separate checks.
"""

import pytest

from synthetic import (RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder,
                       add, const, copy, load, op, reg, store, tmp)
from test_allocation_lifetime import (_begin, _contracts, _finish, _guard, _key,
                                      _run, _writer, models)
from test_external_models import THUNKS
from tdo_v2._call_value_ports import scalar_call_rows
from tdo_v2.memory_contracts import MemoryDefinitionKind


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _case(models, kind="reg", *, barrier=None, offset=4, input_offset=0, width=8, free_after=False,
          address_transport=None):
    builder, birth = _begin()
    _guard(builder)
    helper = FunctionBuilder(0x1800)
    if kind == "mem":
        builder.ins(add(reg(RCX), reg(RSP), const(0x30)), store(reg(RCX), reg(RBX)))
        helper.ins(load(reg(RAX), reg(RDX if address_transport else RCX)))
    else:
        builder.ins(add(reg(RCX), reg(RBX), const(input_offset & ((1 << 64) - 1))))
        if kind == "off":
            helper.ins(add(reg(RAX), reg(RCX), const(offset & ((1 << 64) - 1))))
        else:
            helper.ins(copy(reg(RAX, width), reg(RCX, width)))
    if barrier == "source-call" or barrier == "address-call":
        builder.call(0x1f00)
    elif barrier == "source-alias":
        builder.ins(store(reg(RSI), const(7)))
    source = None
    if address_transport:
        source = _key(builder, 0, "INT_ADD" if address_transport == "plus-zero" else
                      "INT_AND" if address_transport == "and-self" else "COPY")
        if address_transport == "copy-one":
            builder.ins(copy(reg(RDX), reg(RCX)))
        elif address_transport == "copy-two":
            builder.ins(copy(tmp(0x8100), reg(RCX))).ins(copy(reg(RDX), tmp(0x8100)))
        elif address_transport == "plus-zero":
            builder.ins(add(reg(RDX), reg(RCX), const(0)))
        elif address_transport == "and-self":
            builder.ins(op("INT_AND", [reg(RCX), reg(RCX)], reg(RDX)))
        else:
            raise AssertionError(address_transport)
    call = _key(builder, 2, "CALL")
    builder.call(0x1800).ins(copy(reg(RDI), reg(RAX)))
    if free_after:
        builder.ins(copy(reg(RCX), reg(RDI))).call(THUNKS["free"])
    writer = _writer(builder, displacement=None)
    item, analysis = _run(_finish(builder), models, _contracts(models, release=free_after), extra=(helper.ret(),))
    return item, analysis, dict(birth=birth, call=call, writer=writer, address_source=source)


def _pointer(analysis, points):
    writer = points["writer"]
    return analysis.input(writer, analysis.ops[writer].inputs[1])


@pytest.mark.parametrize("kind", ("reg", "off", "mem"))
def test_original_full_width_helper_result_keeps_caller_allocation_identity(models, kind):
    item, analysis, points = _case(models, kind)
    port = scalar_call_rows(item.normalized)[points["call"] + "~0"]
    assert port.row[0] == kind and port.width == 8
    output, = [row for row in analysis.ssa.definitions if row.operation_key == points["call"] + "~0"]
    assert output.kind is MemoryDefinitionKind.DATA_WRITE and output.span.size == 8
    assert output.operation_key not in analysis.ops
    pointer = _pointer(analysis, points)
    assert not pointer.unknown and len(pointer.targets) == 1
    target, = pointer.targets
    assert target.allocation.function == item.key and target.allocation.event == points["birth"]
    assert target.offset == (4 if kind == "off" else 0)
    assert analysis.extent(target.allocation)[0] == 8
    assert analysis.lifetime(pointer, points["writer"]).live
    assert analysis.access(points["writer"]) is not None
    assert any(identity[1] == output.operation_key for identity in pointer.definitions)
    # Proven value equality never upgrades a CALL to universal RAM keeping.
    assert item.proven[points["call"]].callee == "1:1800"


@pytest.mark.parametrize("offset,input_offset,expected", ((-4, 4, 0), (4, 0, 4)))
def test_offset_ports_keep_signed_exact_displacement_not_a_new_allocation(models, offset, input_offset, expected):
    _, analysis, points = _case(models, "off", offset=offset, input_offset=input_offset)
    pointer = _pointer(analysis, points)
    assert not pointer.unknown and len(pointer.targets) == 1
    target, = pointer.targets
    assert target.offset == expected and target.allocation.event == points["birth"]
    assert analysis.access(points["writer"]) is not None


@pytest.mark.parametrize("offset", (-4, 8, (1 << 63) - 1))
def test_offset_result_cannot_make_out_of_allocation_access_owned(models, offset):
    _, analysis, points = _case(models, "off", offset=offset)
    assert analysis.access(points["writer"]) is None


@pytest.mark.parametrize("kind,barrier", (("reg", "source-call"), ("off", "source-call"),
                                         ("mem", "address-call"), ("mem", "source-alias")))
def test_independent_source_or_address_debt_is_not_repaired_by_return_identity(models, kind, barrier):
    item, analysis, points = _case(models, kind, barrier=barrier)
    assert points["call"] + "~0" in scalar_call_rows(item.normalized)
    pointer = _pointer(analysis, points)
    assert pointer.unknown and not analysis.lifetime(pointer, points["writer"]).live
    assert analysis.access(points["writer"]) is None


@pytest.mark.parametrize("width", (1, 4))
def test_partial_result_bytes_cannot_recover_a_full_allocation_pointer(models, width):
    item, analysis, points = _case(models, width=width)
    port = scalar_call_rows(item.normalized)[points["call"] + "~0"]
    assert port.width == width and port.row[0] == "reg"
    pointer = _pointer(analysis, points)
    assert pointer.unknown and analysis.access(points["writer"]) is None


@pytest.mark.parametrize("transport", ("copy-one", "copy-two", "plus-zero", "and-self"))
def test_transitive_clobbered_memory_address_cannot_restore_old_allocation_bytes(models, transport):
    item, analysis, points = _case(models, "mem", barrier="address-call", address_transport=transport)
    # The CALL debt is on an earlier original operand use, not merely a
    # synthetically attached debt on the eventual ~ld staging operation.
    assert any(row.operation_key == points["address_source"] and any(span.start == RCX for span in row.spans)
               for row in item.normalized.call_clobber_reads)
    output, = [definition for definition in analysis.ssa.definitions
               if definition.operation_key == points["call"] + "~0"]
    assert output.kind is MemoryDefinitionKind.DATA_WRITE and output.span.size == 8
    port = scalar_call_rows(item.normalized).get(output.operation_key)
    if transport == "and-self":
        assert port is None  # Its projected memory source is wild.
    else:
        assert port is not None  # Do not pass vacuously at metadata admission.
        assert port.row[0] == "mem" and port.width == 8
    # Placement/wildness may refuse the scalar port first. If it survives,
    # the consumer must still not resurrect the old pointer through its
    # address's COPY/identity chain or through CALL-clobbered slot contents.
    pointer = _pointer(analysis, points)
    assert pointer.unknown and not pointer.targets
    assert not analysis.lifetime(pointer, points["writer"]).live
    assert analysis.access(points["writer"]) is None


@pytest.mark.parametrize("copies", (1, 2, 3))
def test_clean_new_slot_contents_do_not_repair_its_transitively_clobbered_address(models, copies):
    # malloc can change the pre-call RDX address. Rewriting the true stack
    # slot AFTER malloc makes its bytes clean, but says nothing about that
    # old RDX value subsequently copied into the helper's address port.
    builder = FunctionBuilder().sub_rsp(0x60)
    builder.ins(add(reg(RDX), reg(RSP), const(0x30)), copy(reg(RCX), const(8)))
    builder.call(THUNKS["malloc"]).ins(copy(reg(RBX), reg(RAX)))
    _guard(builder)
    stored = _key(builder, 1, "STORE")
    builder.ins(add(tmp(0x8200), reg(RSP), const(0x30)), store(tmp(0x8200), reg(RBX)))
    first = _key(builder, 0, "COPY")
    registers = (RDX, RCX) if copies == 1 else (RDX, RSI, RCX) if copies == 2 else (RDX, RSI, RDI, RCX)
    for source, target in zip(registers, registers[1:]):
        builder.ins(copy(reg(target), reg(source)))
    call = _key(builder, 2, "CALL")
    builder.call(0x1800).ins(copy(reg(RDI), reg(RAX)))
    writer = _writer(builder, displacement=None)
    helper = FunctionBuilder(0x1800).ins(load(reg(RAX), reg(RCX))).ret()
    item, analysis = _run(_finish(builder), models, _contracts(models), extra=(helper,))
    port = scalar_call_rows(item.normalized)[call + "~0"]
    assert port.width == 8 and port.row[0] == "mem"
    assert any(row.operation_key == first and any(span.start == RDX for span in row.spans)
               for row in item.normalized.call_clobber_reads)
    reads = analysis.reads[analysis.actions[port.row[1]]]
    memory, = [read for read in reads if read.span.object_id.kind.value in ("function_relative", "address_space")]
    source = analysis.read_definition(port.row[1], memory.span)
    assert source is not None and analysis.ssa.definitions[source].operation_key == stored
    addresses = [read for read in reads if read is not memory]
    assert addresses and all(analysis.read_definition(port.row[1], read.span) is not None for read in addresses)
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    assert pointer.unknown and not pointer.targets
    assert analysis.access(writer) is None


def test_original_call_address_definition_debt_walk_is_cached(models, monkeypatch):
    from tdo_v2 import normalize

    item, analysis, points = _case(models, "mem")
    port = scalar_call_rows(item.normalized)[points["call"] + "~0"]
    read = next(read for read in analysis.reads[analysis.actions[port.row[1]]]
                if read.span.object_id.kind.value == "register_file")
    identifier = analysis.read_definition(port.row[1], read.span)
    assert identifier is not None and not analysis._call_address_debts
    original, calls = normalize._row_reaches_debt, []

    def counted(graph, node):
        calls.append(node)
        return original(graph, node)

    monkeypatch.setattr(normalize, "_row_reaches_debt", counted)
    assert analysis._clean_call_address(identifier)
    assert analysis._clean_call_address(identifier)
    assert calls == [item.normalized.memory_graph.definition_nodes[identifier]]


@pytest.mark.parametrize("limit", ("queries", "work"))
def test_call_address_debt_check_exhaustion_never_means_clean(models, monkeypatch, limit):
    from tdo_v2 import _allocation_lifetime

    _, analysis, points = _case(models, "mem")
    name = "_CALL_ADDRESS_DEBT_QUERIES" if limit == "queries" else "_CALL_ADDRESS_DEBT_WORK"
    monkeypatch.setattr(_allocation_lifetime, name, 0 if limit == "queries" else 1)
    pointer = _pointer(analysis, points)
    assert pointer.unknown and not pointer.targets
    assert analysis.access(points["writer"]) is None


def test_call_address_debt_walk_does_not_swallow_global_budget_failure(models, monkeypatch):
    from tdo_v2 import normalize
    from tdo_v2.resource_limits import AnalysisBudgetExceeded

    item, analysis, points = _case(models, "mem")
    port = scalar_call_rows(item.normalized)[points["call"] + "~0"]
    read = next(read for read in analysis.reads[analysis.actions[port.row[1]]]
                if read.span.object_id.kind.value == "register_file")
    identifier = analysis.read_definition(port.row[1], read.span)

    def exhausted(*args):
        raise AnalysisBudgetExceeded("work", scope="run")

    monkeypatch.setattr(normalize, "_row_reaches_debt", exhausted)
    with pytest.raises(AnalysisBudgetExceeded) as error:
        analysis._clean_call_address(identifier)
    assert error.value.scope == "run"


def test_later_release_does_not_become_live_because_helper_returned_the_old_pointer(models):
    item, analysis, points = _case(models, free_after=True)
    # Inspect the original result definition independently of the later use;
    # that use may itself have an additional free's register clobber debt.
    identifier, output = next((identifier, row) for identifier, row in enumerate(analysis.ssa.definitions)
                              if row.operation_key == points["call"] + "~0")
    assert points["call"] + "~0" in scalar_call_rows(item.normalized)
    pointer = analysis.definition(identifier, output.span)
    assert not pointer.unknown and pointer.targets
    assert not analysis.lifetime(pointer, points["writer"]).live
    assert analysis.access(points["writer"]) is None
