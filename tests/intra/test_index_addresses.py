"""Index addresses (array step C1, docs 25.8): scaled atoms and boundary
atoms (INT_SEXT / INT_ZEXT of an expression with atoms) in address
expressions; the exact object of an atom tuple; wild index objects; the wrap
seam bound."""

import random

import pytest

import test_graph_fidelity as fidelity
from graph_oracle import check
from synthetic import (
    R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, normalize,
    normalize_with_observation, op, operation_node_at, reg, slice_from, store, straight, tmp,
)

H = 1 << 63


def _element(out, base, index_register, scale, displacement=0, *, index_size=4, extend="INT_SEXT"):
    """out = base + scale * extend(index) + displacement (four temporaries)."""
    wide, scaled = tmp(0x400), tmp(0x408)
    ops = [op(extend, [reg(index_register, index_size)], wide),
           op("INT_MULT", [wide, const(scale)], scaled),
           add(out, reg(base), scaled)]
    if displacement:
        ops.append(add(out, out, const(displacement % (1 << 64))))
    return ops


def _load_node(function, instruction):
    """The LOAD operation node of instruction ``instruction``."""
    from synthetic import CODE_BASE, RAM

    prefix = f"op:{RAM}:{CODE_BASE + 4 * instruction:x}:"
    graph = function.dependencies
    for node in range(graph.node_count):
        record = graph.node(node)
        if record.kind.name == "OPERATION" and record.key.startswith(prefix) and record.key.endswith(":LOAD"):
            return node
    raise KeyError(prefix)


def _slice_of_load(builder, instruction):
    function = normalize(builder)
    return slice_from(function, _load_node(function, instruction))


def _bytes(register):
    return set(range(register, register + 8))


def test_the_same_element_is_one_exact_place():
    """a[i] = rdx; a[i] = rcx; rax = a[i]: the second write kills the first."""
    t = tmp(0x100)
    found = _slice_of_load(straight(
        [*_element(t, RDI, RSI, 8), store(t, reg(RDX))],
        [*_element(t, RDI, RSI, 8), store(t, reg(RCX))],
        [*_element(t, RDI, RSI, 8), load(reg(RAX), t)],
    ), 2)
    assert found.is_complete
    assert _bytes(RCX) <= found.register_bytes and not _bytes(RDX) & found.register_bytes


def test_two_fields_of_one_element_are_separate():
    """a[i].f0 = rdx; a[i].f8 = rcx; rax = a[i].f0 (16-byte elements)."""
    t = tmp(0x100)
    found = _slice_of_load(straight(
        [*_element(t, RDI, RSI, 16), store(t, reg(RDX))],
        [*_element(t, RDI, RSI, 16, 8), store(t, reg(RCX))],
        [*_element(t, RDI, RSI, 16), load(reg(RAX), t)],
    ), 2)
    assert found.is_complete
    assert _bytes(RDX) <= found.register_bytes and not _bytes(RCX) & found.register_bytes


def test_another_index_may_be_the_same_element():
    """a[i] = rdx; a[j] = rcx; rax = a[i]: j may equal i -- both origins."""
    t = tmp(0x100)
    found = _slice_of_load(straight(
        [*_element(t, RDI, RSI, 8), store(t, reg(RDX))],
        [*_element(t, RDI, R8, 8), store(t, reg(RCX))],
        [*_element(t, RDI, RSI, 8), load(reg(RAX), t)],
    ), 2)
    assert _bytes(RDX) <= found.register_bytes and _bytes(RCX) <= found.register_bytes
    assert not found.is_complete


def test_an_element_write_may_land_on_a_plain_pointer_slot():
    """*(rdi) = rdx; a[i] = rcx; rax = *(rdi): i may be 0."""
    t = tmp(0x100)
    found = _slice_of_load(straight(
        [store(reg(RDI), reg(RDX))],
        [*_element(t, RDI, RSI, 8), store(t, reg(RCX))],
        [load(reg(RAX), reg(RDI))],
    ), 2)
    assert _bytes(RDX) <= found.register_bytes and _bytes(RCX) <= found.register_bytes


def test_an_index_object_reaches_the_private_frame():
    """Astra's counterexample: rdi = entry rsp + 8 (a caller-frame pointer),
    esi = -7: rdi + 8*sext(esi) is this function's frame slot [rsp+0x10]."""
    t, u = tmp(0x100), tmp(0x200)
    builder = (FunctionBuilder().sub_rsp(0x40)
               .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RBX)))
               .ins(*_element(u, RDI, RSI, 8), store(u, reg(RDX)))
               .ins(add(t, reg(RSP), const(0x10)), load(reg(RAX), t))
               .add_rsp(0x40).ret())
    function = normalize(builder)
    found = slice_from(function, _load_node(function, 3))
    assert _bytes(RDX) <= found.register_bytes and not found.is_complete
    normalized, observation = normalize_with_observation(builder)
    report = check(normalized, observation, seeds=range(2),
                   register_pools=lambda seed: {RSP: 0x7000_0000, RDI: 0x7000_0008, RSI: 0xFFFF_FFF9})
    assert report.runs and report.silent == []


def test_displacements_at_the_wrap_seam_are_not_placed():
    """Astra's counterexample: one tuple, displacements 2^63 - 1 (2 bytes) and
    -2^63 (1 byte) overlap modulo 2^64 though their linear spans do not --
    both are refused (unknown accesses): the load keeps the store's value."""
    t = tmp(0x100)
    found = _slice_of_load(straight(
        [add(t, reg(RDI), const(H - 1)), store(t, reg(RDX, 2))],
        [add(t, reg(RDI), const(H)), load(reg(RAX, 1), t)],
    ), 1)
    assert set(range(RDX, RDX + 2)) & found.register_bytes
    assert not found.is_complete


def test_a_loop_variant_index_stays_unknown():
    """for (i = 0; ...; i++) a[i] = rdx; rax = *(rdi): the index has no
    single value -- no expression, the write is unknown."""
    t = tmp(0x100)
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder()
               .ins(copy(reg(RSI, 4), const(0, 4)))
               .label("top")
               .ins(*_element(t, RDI, RSI, 8), store(t, reg(RDX)))
               .ins(add(reg(RSI, 4), reg(RSI, 4), const(1, 4)))
               .cbranch("top", flag, op("INT_NOTEQUAL", [reg(RSI, 4), reg(RCX, 4)], flag))
               .ins(load(reg(RAX), reg(RDI)))
               .ret())
    function = normalize(builder)
    found = slice_from(function, _load_node(function, 5))
    assert _bytes(RDX) <= found.register_bytes and not found.is_complete


def test_scaling_cancels_and_wraps_in_the_ring():
    from tdo_v2.relative_memory import _AddressExpression, _scaled

    value = _AddressExpression(((7, 1), (9, 3)), 5, 8)
    assert _scaled(value, 1 << 63, 8).atoms == ((7, -(1 << 63)), (9, -(1 << 63)))
    assert _scaled(_scaled(value, 1 << 62, 8), 4, 8).atoms == ()
    assert _scaled(value, 0, 8).atoms == () and _scaled(value, 0, 8).displacement == 0
    assert _scaled(_AddressExpression(((7, 1),), 0, 4), 1 << 31, 4).atoms == ((7, -(1 << 31)),)


def test_a_shift_at_or_above_the_width_gives_zero():
    """rcx = rdi << 64 (p-code: 0); *(rcx) = rdx; rax = *(0)."""
    t = tmp(0x100)
    found = _slice_of_load(straight(
        [op("INT_LEFT", [reg(RDI), const(64, 1)], reg(RCX))],
        [store(reg(RCX), reg(RDX))],
        [load(reg(RAX), const(0))],
    ), 2)
    assert _bytes(RDX) <= found.register_bytes


def test_the_switch_off_keeps_index_writes_unknown(monkeypatch):
    t = tmp(0x100)
    builder = straight(
        [*_element(t, RDI, RSI, 8), store(t, reg(RDX))],
        [*_element(t, RDI, RSI, 8), load(reg(RAX), t)],
    )
    assert _slice_of_load(builder, 1).is_complete
    monkeypatch.setenv("TDO_V2_INDEX_ADDRESSES", "0")
    assert not _slice_of_load(builder, 1).is_complete


# -- random index programs under the graph oracle -----------------------------------

_BASES = (RDI, RBX)
_INDEXES = ((RSI, 4, "INT_SEXT"), (RCX, 4, "INT_ZEXT"), (R8, 2, "INT_SEXT"), (R9, 1, "INT_ZEXT"))
_VALUES = (RAX, RDX, R8, R9)


def _random_index_function(rng):
    t = tmp(0x100)
    rows = []
    for _ in range(rng.randint(3, 9)):
        base = rng.choice(_BASES)
        index, size, extend = rng.choice(_INDEXES)
        scale = rng.choice((1, 2, 4, 8, 12, 16, 24))
        displacement = rng.choice((0, 0, 4, 8, -8))
        width = rng.choice((1, 2, 4, 8))
        address = _element(t, base, index, scale, displacement, index_size=size, extend=extend) \
            if rng.random() < 0.8 else [add(t, reg(base), const(displacement % (1 << 64)))]
        if rng.random() < 0.5:
            rows.append([*address, store(t, reg(rng.choice(_VALUES), width))])
        else:
            rows.append([*address, load(reg(rng.choice(_VALUES), width), t)])
        if rng.random() < 0.15:   # an index register overwritten between uses
            rows.append([add(reg(index, 4), reg(index, 4), const(1, 4))])
    return straight(*rows)


def _pools(seed):
    rng = random.Random(seed)
    values = {RSP: 0x7000_0000}
    base = rng.choice((0x5000_0000, 0x5000_0100))
    for register in _BASES:
        values[register] = rng.choice((base, base + 8, base + 0x40))
    for register in (RSI, RCX, R8, R9):
        values[register] = rng.choice((0, 1, 2, 3, (-1) % (1 << 64), (-2) % (1 << 64), 8))
    for register in _VALUES:
        values.setdefault(register, rng.getrandbits(64))
    return values


@pytest.mark.parametrize("chunk", range(3))
def test_random_index_programs_have_no_silent_miss(chunk):
    silent, runs = [], 0
    for seed in range(chunk * 60, chunk * 60 + 60):
        builder = _random_index_function(random.Random(70_000 + seed))
        normalized, observation = normalize_with_observation(builder)
        report = check(normalized, observation, seeds=range(6), register_pools=_pools)
        runs += report.runs
        silent += [(seed, item) for item in report.silent]
    assert runs > 0
    assert silent == [], silent[:3]


def test_merging_index_tuples_is_caught(monkeypatch):
    """A mutation: tuples differing only in coefficients become one object
    (a[i] and a[2i] taken as the same place) -- the oracle must see misses."""
    import tdo_v2.relative_memory as relative_memory

    original = relative_memory._address_atom_key
    monkeypatch.setattr(relative_memory, "_address_atom_key",
                        lambda atoms: original(tuple((atom, 1) for atom, _ in atoms)))
    silent = []
    for seed in range(120):
        builder = _random_index_function(random.Random(70_000 + seed))
        normalized, observation = normalize_with_observation(builder)
        silent += check(normalized, observation, seeds=range(6), register_pools=_pools).silent
    assert silent


def test_an_opaque_value_of_an_index_is_wild():
    """Astra (C1 round 1): an opaque operation over an index expression must
    keep its wildness -- (zext(edi) & mask) - 16 may be a caller-frame pointer
    moved into this function's frame."""
    from types import SimpleNamespace
    from tdo_v2.relative_memory import _AddressExpression, _Projector

    function = normalize(straight([store(reg(RDI), reg(RDX))]))
    boundary, entry, scaled_input, opaque = 11, 12, 13, 14
    stub = SimpleNamespace(
        _ssa=function.memory_ssa, _import_atoms=set(), _definition_atoms=set(), _fresh_atoms=set(),
        _nonstack_atoms=set(), _nonstack_extent={}, _eligible_atoms={}, wild_definitions={}, _boundary={boundary: ("zext", 4, 8, (0, 1 << 32))}, wild_objects=set(),
        fresh_objects=set(), nonstack_objects=set(), _stack_atoms=(None, frozenset(), None), _stack_derived=set())
    stub._is_stack_derived = lambda atom: _Projector._is_stack_derived(stub, atom)
    stub._pre_escape_rows = lambda address: _Projector._pre_escape_rows(stub, address)
    for inputs, wild in (((_AddressExpression(((boundary, 1),), 0, 8),), True),
                         ((_AddressExpression(((scaled_input, 8),), 0, 8),), True),
                         ((_AddressExpression(((entry, 1),), 0, 8),), False)):
        stub._definition_atoms, stub.wild_objects = set(), set()
        _Projector._note_opaque_atom(stub, opaque, inputs)
        found = _Projector._relative_object(stub, _AddressExpression(((opaque, 1),), -16, 8, 0), 1)
        assert (found in stub.wild_objects) is wild, inputs


@pytest.mark.parametrize("bits", [32, 64])
def test_the_seam_bound_follows_the_address_width(bits):
    from tdo_v2.relative_memory import _relative_start

    quarter = 1 << (bits - 2)
    assert _relative_start(quarter - 1, bits, 8) == (1 << bits) + quarter - 1
    assert _relative_start(-(quarter - 1), bits, 8) == (1 << bits) - quarter + 1
    for d in (quarter, -quarter, (1 << (bits - 1)) - 1, -(1 << (bits - 1))):
        assert _relative_start(d, bits, 1) is None
    # an anchored access: the total of the anchor's and the added displacement
    assert _relative_start((quarter - 8) + 16, bits, 1) is None
    assert _relative_start((1 << bits) - 8, bits, 8) == (1 << bits) - 8      # -8 in the ring
    assert _relative_start(8, bits, quarter) is None


def test_an_index_reread_after_a_wild_write_is_not_the_same_place():
    """i = slot; a[i] = rdx; *q = 1 (q may be the slot); i' = slot; r9 = a[i']:
    the two reads of the slot are one definition, but the second carries the
    wild write's alias debt -- a[i'] must not be taken as a[i] silently."""
    from test_stale_projection_alias import _image, _pools as slot_pools, _slot_rewritten

    t, u = tmp(0x100), tmp(0x180)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x20)), store(t, const(0)))
               .ins(add(t, reg(RSP), const(0x20)), load(reg(RSI, 4), t))
               .ins(*_element(u, RBX, RSI, 8), store(u, reg(RDX))))
    _slot_rewritten(builder, lambda t: [copy(t, const(1))])
    builder = (builder
               .ins(add(t, reg(RSP), const(0x20)), load(reg(RCX, 4), t))
               .ins(*_element(u, RBX, RCX, 8), load(reg(R9), u))                        # instruction 6
               .add_rsp(0x80).ret())
    normalized, observation = normalize_with_observation(builder)
    reload = slice_from(normalized, _load_node(normalized, 6))
    assert _bytes(RDX) & reload.register_bytes or not reload.is_complete

    def pools(seed):
        return {**slot_pools(seed), RBX: 0x5000_0000, RDX: 0x1111_2222_3333_4444}

    report = check(normalized, observation, seeds=range(6), register_pools=pools, image=_image)
    assert report.runs and report.silent == []
