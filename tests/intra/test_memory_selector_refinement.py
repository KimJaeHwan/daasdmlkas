"""Space selectors carry IDs, independently of address and access widths.

The existing SSA/refinement and raw interpreter provide all proof machinery.
No frame nonaccess premise is supplied in the OFF rows of this matrix.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from graph_oracle import check
from synthetic import RAM, RAX, RCX, RDX, RSP, const, reg, slice_from
from test_forward_memory_refinement import READ, WRITER, _baseline, _body, _target
from tdo_v2 import may_alias
from tdo_v2._forward_memory import RefinementRefused, prepare_memory_refinement
from tdo_v2.forward import probe
from tdo_v2.normalize import FunctionNormalizer


FRAME = "entry-values-do-not-address-the-new-frame"
HOME = "win64-home-space-callee-private"


@pytest.fixture(params=(("sparse", False), ("dense", False), ("sparse", True), ("dense", True)))
def policy(request, monkeypatch):
    engine, frame = request.param
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    token = may_alias.ENTRY_VALUES_NOT_FRAME.set(frame)
    try:
        yield frame
    finally:
        may_alias.ENTRY_VALUES_NOT_FRAME.reset(token)


def _selectors(body, store_width, load_width):
    for instruction in body._rows:
        instruction.ops = [(code, [const(RAM, store_width if code == "STORE" else load_width), *inputs[1:]], out)
                           if code in ("LOAD", "STORE") else (code, inputs, out)
                           for code, inputs, out in instruction.ops]
    return body


def _read(normalized, key):
    ssa = normalized.memory_ssa
    (row,) = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == key
              and row.span.object_id.kind.value in ("function_relative", "address_space")]
    return row


def _oracle(original, replay):
    for normalized in (original.normalized, replay):
        result = check(normalized, original.unit.observation, seeds=range(8), register_pools=lambda seed: {
            RSP: 0x70000000, RCX: seed, RDX: 0x12345678 + seed})
        assert result.runs == 8 and result.checked and not result.unsupported
        assert not result.opaque_opcodes and not result.silent, result.silent


@pytest.mark.parametrize("store_width,load_width", ((2, 8), (4, 8), (8, 4)))
def test_same_space_different_selector_widths_recover_the_original_definition(policy, store_width, load_width):
    original, options, plan = _baseline(_selectors(_body(), store_width, load_width))
    (proof,) = _target(plan)
    assert proof.span.size == 4
    assert any(row.operation_key == READ and WRITER in row.plain for row in original.normalized.may_alias_reads)
    old, _ = probe(original.normalized, READ, (proof.span,))
    assert old[proof.span] is None
    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    assert not any(row.operation_key == READ and WRITER in row.writers for row in replay.may_alias_reads)
    found, requires = probe(replay, READ, (proof.span,))
    assert found[proof.span] is not None
    definition = replay.memory_ssa.definitions[found[proof.span]]
    assert definition.operation_key == "1:1004:2:STORE"
    assert all(set(plan.requires) <= set(labels) for labels in (requires, replay.forward_memory_requires))
    if not policy:
        assert not replay.assumes_entry_values_not_frame and not replay.forward_inputs.entry_values_not_frame
        assert not {FRAME, HOME} & set(plan.requires)
        assert not {FRAME, HOME} & set(requires)
        for item in plan.proofs:
            assert not {FRAME, HOME} & set(item.read_fact.requires + item.write_fact.requires)
    _oracle(original, replay)


@pytest.mark.parametrize("displacement,width", ((0x40, 4), (0x3D, 4), (0x3F, 8)))
def test_real_or_partial_return_slot_writers_are_never_excluded(policy, displacement, width):
    body = _selectors(_body(displacement=displacement, width=width), 4, 8)
    reader = f"1:{body._address(len(body._rows) - 1):x}:0:LOAD"
    original, options, plan = _baseline(body)
    assert not plan or not any(proof.read == reader and proof.writer == WRITER for proof in plan.proofs)
    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan) if plan else \
        original.normalized
    assert any(row.operation_key == reader and WRITER in row.plain for row in replay.may_alias_reads)
    graph = replay.dependencies
    view = slice_from(replay, graph.node_for_key("op:" + reader))
    assert graph.node_for_key("op:" + WRITER) in view.result.reachable_nodes
    assert _read(replay, reader).span.size == 8
    _oracle(original, replay)


@pytest.mark.parametrize("role,address_bytes", (("read", 2), ("read", 4), ("write", 2), ("write", 4)))
def test_selector_encoding_width_does_not_allow_truncated_address_operands(policy, role, address_bytes):
    body = _selectors(_body(), 4, 8)
    instruction, ordinal = (4, 0) if role == "read" else (3, 4)
    code, inputs, output = body._rows[instruction].ops[ordinal]
    body._rows[instruction].ops[ordinal] = (code, [inputs[0], {**inputs[1], "byte_size": address_bytes},
                                                *inputs[2:]], output)
    original, _, plan = _baseline(body)
    assert not _target(plan)
    assert any(row.operation_key == READ for row in original.normalized.may_alias_reads)


@pytest.mark.parametrize("selector", (const(2, 4), const(4, 8), reg(RAX)))
def test_different_or_nonconstant_writer_selectors_do_not_authorize_a_space_proof(policy, selector):
    body = _selectors(_body(), 4, 8)
    code, inputs, output = body._rows[3].ops[4]
    body._rows[3].ops[4] = (code, [selector, *inputs[1:]], output)
    _, _, plan = _baseline(body)
    assert not _target(plan)


def test_nonmemory_or_narrow_space_evidence_cannot_authorize_a_64bit_proof(policy):
    original, options, plan = _baseline(_selectors(_body(), 4, 8))
    assert _target(plan)
    inputs = original.normalized.forward_inputs
    for changes in ({"address_size_bits": 32}, {"is_memory_space": False}):
        spaces = tuple(replace(space, **changes) if space.space_id == RAM else space
                       for space in inputs.address_spaces)
        normalized = replace(original.normalized, forward_inputs=replace(inputs, address_spaces=spaces))
        changed = SimpleNamespace(unit=original.unit, key=original.key, normalized=normalized, declared={},
                                  inherited_assumptions=frozenset(), proven={})
        assert not _target(prepare_memory_refinement(changed, options))


def test_on_off_policy_cannot_be_changed_after_building_a_selector_proof(policy):
    original, options, plan = _baseline(_selectors(_body(), 4, 8))
    assert _target(plan)
    token = may_alias.ENTRY_VALUES_NOT_FRAME.set(not policy)
    try:
        with pytest.raises(RefinementRefused):
            plan.verify()
        with pytest.raises(RefinementRefused):
            FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    finally:
        may_alias.ENTRY_VALUES_NOT_FRAME.reset(token)
