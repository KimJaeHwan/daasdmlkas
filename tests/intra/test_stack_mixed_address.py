"""A stack address mixed with another value (``rsp + rdi``, ``2*rsp``) reaches
the function's private frame: it is a stack address, not "another base" the
private-frame rule excludes (``relative_memory._relative_object`` marks its
object wild, like a loaded pointer)."""

import pytest

from pcode_interpreter import Interpreter
from program_oracle import check_program
from synthetic import (
    CODE_BASE, CONST, RAM, RAX, RBP, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load,
    op, operation_node_at,
    program_units, reg, slice_from, store, sub, tmp,
)
from tdo_v2.interprocedural import analyze_units


def _slice_of_rax(builder):
    (unit,) = program_units(builder)
    normalized = analyze_units([unit])["1:1000"].normalized
    return slice_from(normalized, operation_node_at(normalized, 3, 1))


def _write_then_read(address_ops):
    """[rsp+0x10] = rsi; [address] = rdx; rax = [rsp+0x10]."""
    t, u = tmp(0x100), tmp(0x200)
    return (FunctionBuilder().sub_rsp(0x40)
            .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RSI)))
            .ins(*address_ops(u), store(u, reg(RDX)))
            .ins(add(t, reg(RSP), const(0x10)), load(reg(RAX), t))
            .add_rsp(0x40).ret())


def _bytes(register):
    return set(range(register, register + 8))


@pytest.mark.parametrize("address_ops", [
    lambda u: (add(u, reg(RSP), reg(RDI)),),        # rsp + rdi
    lambda u: (add(u, reg(RDI), reg(RSP)),),        # rdi + rsp
    lambda u: (add(u, reg(RSP), reg(RSP)),),        # 2 * rsp
], ids=["rsp+rdi", "rdi+rsp", "2rsp"])
def test_a_write_through_a_mixed_stack_address_may_land_in_the_frame(address_ops):
    found = _slice_of_rax(_write_then_read(address_ops))
    assert _bytes(RDX) <= found.register_bytes   # rdi = 0x10: the frame slot
    assert _bytes(RSI) <= found.register_bytes
    assert not found.is_complete


def test_a_write_through_an_entry_pointer_stays_out_of_the_frame():
    t = tmp(0x100)
    found = _slice_of_rax(FunctionBuilder().sub_rsp(0x40)
                          .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RSI)))
                          .ins(store(reg(RDI), reg(RDX)))
                          .ins(add(t, reg(RSP), const(0x10)), load(reg(RAX), t))
                          .add_rsp(0x40).ret())
    assert not _bytes(RDX) & found.register_bytes
    assert found.is_complete


def test_a_read_through_a_mixed_stack_address_may_see_a_frame_write():
    """[rsp+0x10] = rsi; rax = [rsp + rdi]."""
    t, u = tmp(0x100), tmp(0x200)
    builder = (FunctionBuilder().sub_rsp(0x40)
               .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RSI)))
               .ins(add(u, reg(RSP), reg(RDI)))
               .ins(load(reg(RAX), u))
               .add_rsp(0x40).ret())
    (unit,) = program_units(builder)
    normalized = analyze_units([unit])["1:1000"].normalized
    found = slice_from(normalized, operation_node_at(normalized, 3, 0))
    assert _bytes(RSI) <= found.register_bytes
    assert not found.is_complete


@pytest.mark.parametrize("address_ops", [
    lambda u: (sub(u, reg(RSP), reg(RDI)),),                                   # rsp - rdi
    lambda u: (copy(reg(RBP), reg(RSP)), add(u, reg(RBP), reg(RDI))),         # rbp = rsp; rbp + rdi
], ids=["rsp-rdi", "rbp+rdi"])
def test_other_mixed_stack_addresses_may_land_in_the_frame(address_ops):
    found = _slice_of_rax(_write_then_read(address_ops))
    assert _bytes(RDX) <= found.register_bytes
    assert not found.is_complete


def test_the_run_where_the_mixed_address_hits_the_slot_is_explained():
    """A directed run: rdi = 0x10 makes rsp + rdi the slot rax reloads (random
    register pools rarely produce that collision)."""
    from graph_oracle import check
    from synthetic import normalize_with_observation

    normalized, observation = normalize_with_observation(_write_then_read(lambda u: (add(u, reg(RSP), reg(RDI)),)))
    report = check(normalized, observation, seeds=range(2), register_pools=lambda seed: {RSP: 0x7000_0000, RDI: 0x10})
    assert report.runs and report.silent == []


def test_every_part_of_the_stack_pointer_is_a_stack_atom():
    """Entry atoms of any register span overlapping the stack pointer (a
    part, a wider pair, an odd width) are stack atoms; the whole one is the
    stack object's own atom; another register's are not."""
    from tdo_v2.may_alias import _unit_stub
    from tdo_v2.model import ResolvedStorage, StorageRef, VarnodeKind
    from tdo_v2.relative_memory import _stable_storage_key, _stack_atoms
    from tdo_v2.span_geometry import ByteSpan
    from tdo_v2.storage import _resolve_validated_storage

    (unit,) = program_units(_write_then_read(lambda u: (add(u, reg(RSP), reg(RDI)),)))
    scopes = unit.scopes
    whole, overlapping, _, _ = _stack_atoms(_unit_stub(scopes), unit.observation, scopes.resolution_context,
                                      scopes.program.evidence.address_spaces)

    def span_of(offset, size):
        resolved = _resolve_validated_storage(StorageRef(VarnodeKind.REGISTER, "", offset, size, space_id=REG),
                                              scopes.resolution_context)
        assert type(resolved) is ResolvedStorage
        return resolved.span

    rsp = span_of(RSP, 8)
    assert whole == _stable_storage_key(rsp)
    for start, width in ((rsp.start, 4), (rsp.start + 3, 3), (rsp.start + 7, 1), (rsp.start - 2, 5),
                         (rsp.start - 8, 16), (rsp.start + 1, 6)):
        assert _stable_storage_key(ByteSpan(rsp.object_id, start, width)) in overlapping, (start, width)
    assert _stable_storage_key(span_of(RDI, 8)) not in overlapping


def _callee_writing(address_ops):
    """callee: sub rsp; [address] = rcx; add rsp; ret."""
    from synthetic import CODE_BASE

    u = tmp(0x200)
    return (FunctionBuilder(entry=CODE_BASE + 0x800).sub_rsp(0x28)
            .ins(*address_ops(u), store(u, reg(RCX)))
            .add_rsp(0x28).ret())


@pytest.mark.parametrize("address_ops, keeps", [
    (lambda u: (add(u, reg(RSP), const(8)),), True),     # its own frame: invisible to the caller
    (lambda u: (op("INT_XOR", [reg(RSP), reg(RDI)], u),), False),  # nonlinear, still unexportable
], ids=["frame", "nonlinear"])
def test_a_callee_writing_through_a_mixed_stack_address_does_not_preserve_memory(address_ops, keeps):
    from synthetic import CODE_BASE

    caller = FunctionBuilder().sub_rsp(0x28).call(CODE_BASE + 0x800).add_rsp(0x28).ret()
    results = analyze_units(program_units(caller, _callee_writing(address_ops)))
    (effect,) = [effect for key, effect in results["1:1000"].proven.items() if key.endswith(":CALL")]
    assert effect.preserves_memory is keeps


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_typed_mixed_stack_run_keeps_only_other_memory_and_covers_every_overlapping_caller_byte(monkeypatch, engine):
    """The exported indexed write may hit the caller's private frame. Its
    SP is an identity index: the raw CALL push must be applied exactly once."""
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    slot = tmp(0x100)
    caller = (FunctionBuilder().sub_rsp(0x40)
              .ins(add(slot, reg(RSP), const(0x10)), store(slot, reg(RSI)))
              .call(CODE_BASE + 0x800)
              .ins(add(slot, reg(RSP), const(0x10)), load(reg(RAX), slot)).add_rsp(0x40).ret())
    units = program_units(caller, _callee_writing(lambda u: (add(u, reg(RSP), reg(RDI)),)))
    results = analyze_units(units)
    item, callee = results["1:1000"], results["1:1800"]
    (relation,) = [value for _, value in callee.summary.address_relations]
    assert (relation.base.start, relation.index.start, relation.extend, relation.preoffset, relation.scale) == \
        (RDI, RSP, "identity", 0, 1)
    (call, effect), = item.normalized.proven_call_effects
    assert effect.preserves_memory  # except its explicitly exported run, not "no writes"
    (run,) = [run for run in effect.memory_runs if run.write.index is not None]
    assert run.write.anchor.start == RDI and run.write.index.register.start == RSP
    assert run.write.displacement == -0x28 and run.write.index.preoffset == 0
    (writer, _, reference), = [row for row in item.normalized.call_anchors
                               if type(row[2]) is tuple and row[2][0] == "indexed"]
    assert reference[3:] == (8, "identity", (1 << 64) - 8, 1)
    definitions = [definition for definition in item.normalized.memory_ssa.definitions
                   if definition.operation_key == writer and definition.span.size == 8]
    assert definitions and all(definition.span.object_id in item.normalized.wild_objects for definition in definitions)
    assert all(definition.span.start == (1 << 64) - 0x70 for definition in definitions)
    found = slice_from(item.normalized, operation_node_at(item.normalized, 3, 1))
    assert not found.is_complete and _bytes(RCX) <= found.register_bytes
    offsets = (0x40, 0x3C, 0x3F, 0x41, 0x44, 0x47, 0x48, 0x60)

    def pools(seed):
        return {RSP: 0x70000000, RDI: offsets[seed], RSI: 0x1122334455667700 + seed,
                RCX: 0xA1B2C3D4E5F60700 + seed}

    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(8),
                           register_pools=pools, havoc_calls=(REG, RSP, 8))
    assert report.runs == 8 and report.checked and report.through_calls and report.place_covered
    assert not report.silent and not report.unsupported and not report.place_failed and not report.place_unlocated_only
    counts = []
    for seed, offset in enumerate(offsets):
        machine = Interpreter(item.unit.observation, constant_space=CONST, seed=seed,
                              program=program, havoc_calls=(REG, RSP, 8))
        for register, value in pools(seed).items():
            machine.preset(REG, register, 8, value)
        actual = machine.run()
        assert actual.completed
        target, demand = 0x70000000 - 0x70 + offset, 0x70000000 - 0x30
        for byte in range(8):
            assert machine._byte(RAM, target + byte) == ((pools(seed)[RCX] >> (8 * byte)) & 0xFF, call)
        expected = {(demand + byte, call if target <= demand + byte < target + 8 else "1:1004:1:STORE")
                    for byte in range(8)}
        observed = {(row.offset, row.writer) for row in actual.dependencies
                    if row.reader == "1:100c:1:LOAD" and row.space_id == RAM}
        assert observed == expected
        counts.append(sum(owner == call for _, owner in expected))
    assert counts == [8, 4, 7, 7, 4, 1, 0, 0]


def test_an_object_on_an_opaque_atom_computed_from_the_stack_is_wild():
    """An opaque atom built from a stack-derived input (``_stack_derived``)
    marks its objects wild; the stack atom alone stays the stack object."""
    from types import SimpleNamespace
    from tdo_v2.relative_memory import _AddressExpression, _Projector

    (unit,) = program_units(_write_then_read(lambda u: (add(u, reg(RSP), reg(RDI)),)))
    normalized = analyze_units([unit])["1:1000"].normalized
    stack, opaque = 11, 22
    stub = SimpleNamespace(
        _ssa=normalized.memory_ssa, _import_atoms=set(), _definition_atoms=set(), _fresh_atoms=set(),
        _nonstack_atoms=set(), _nonstack_extent={}, _eligible_atoms={}, wild_definitions={}, _boundary={}, wild_objects=set(), fresh_objects=set(),
        nonstack_objects=set(), _stack_atoms=(stack, frozenset({stack}), None), _stack_derived={opaque})
    stub._is_stack_derived = lambda atom: _Projector._is_stack_derived(stub, atom)
    stub._pre_escape_rows = lambda address: _Projector._pre_escape_rows(stub, address)
    on_opaque = _Projector._relative_object(stub, _AddressExpression(((opaque, 1),), 0, 8, 0), 1)
    on_stack = _Projector._relative_object(stub, _AddressExpression(((stack, 1),), 0, 8, 0), 1)
    assert on_opaque in stub.wild_objects
    assert on_stack not in stub.wild_objects


def test_an_entry_atom_of_a_wide_span_holding_the_stack_pointer_is_stack_derived():
    """A span wider than the enumerated widths (32 bytes holding rsp) is
    classified when its entry atom is created (Astra round 2)."""
    from types import SimpleNamespace
    from tdo_v2.relative_memory import _Projector
    from tdo_v2.span_geometry import ByteSpan

    (unit,) = program_units(_write_then_read(lambda u: (add(u, reg(RSP), reg(RDI)),)))
    normalized = analyze_units([unit])["1:1000"].normalized
    register_file = next(d.span.object_id for d in normalized.memory_ssa.definitions
                         if d.span.object_id.kind.name == "REGISTER_FILE")
    rsp = ByteSpan(register_file, RSP, 8)
    stub = SimpleNamespace(_stack_atoms=(1, frozenset({1}), rsp), _stack_derived=set())
    _Projector._note_entry_atom(stub, ByteSpan(register_file, RSP - 8, 32), 5)
    _Projector._note_entry_atom(stub, ByteSpan(register_file, RSP + 8, 32), 6)    # starts past rsp
    _Projector._note_entry_atom(stub, ByteSpan(register_file, RSP - 32, 32), 7)   # ends at rsp
    assert stub._stack_derived == {5}
    assert _Projector._is_stack_derived(stub, 5) and not _Projector._is_stack_derived(stub, 6)
