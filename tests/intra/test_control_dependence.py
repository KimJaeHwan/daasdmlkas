"""Control dependence edges (``tdo_v2.control_dependence``).

``BackwardSliceQuery`` stays data-only by default; ``include_control=True``
also follows ``control_dependence`` edges, so ``if (secret) x = 1`` reaches
``secret``.
"""

import random

import pytest

from graph_oracle import check_control
from synthetic import (
    RAX, RBX, RCX, RDX, ZF,
    FunctionBuilder, const, copy, normalize_with_observation, op, operation_node_at,
    reg,
)
from tdo_v2.query import BackwardSliceQuery
import test_graph_fidelity as fidelity


def _reach(function, index, ordinal=0, *, control):
    node = operation_node_at(function, index, ordinal)
    result = BackwardSliceQuery().run(function, node, include_control=control)
    return {function.dependencies.node(n).label for n in result.reachable_nodes}, result


def _if_else():
    """if (ZF) RAX = 1 else RAX = 0;  RCX = RAX;  RDX = RBX."""
    return (
        FunctionBuilder()
        .cbranch("else", reg(ZF, 1))          # 0
        .ins(copy(reg(RAX), const(1)))        # 1
        .branch("join")                       # 2
        .label("else")
        .ins(copy(reg(RAX), const(0)))        # 3
        .label("join")
        .ins(copy(reg(RCX), reg(RAX)))        # 4
        .ins(copy(reg(RDX), reg(RBX)))        # 5
        .ret()
    )


def _reaches_flag(labels):
    return any("register_file" in label and label.endswith(f":{ZF:x}:1") for label in labels)


def test_if_else_value_reaches_condition_only_with_control():
    function, _ = normalize_with_observation(_if_else())
    data, _ = _reach(function, 4, control=False)
    control, result = _reach(function, 4, control=True)
    assert not _reaches_flag(data)
    assert _reaches_flag(control)
    assert result.is_complete


def test_code_after_the_join_is_not_control_dependent():
    function, _ = normalize_with_observation(_if_else())
    control, _ = _reach(function, 5, control=True)
    assert not _reaches_flag(control)


def test_if_only_assignment_reaches_condition():
    """RAX = 0; if (ZF) RAX = 1; RCX = RAX."""
    builder = (
        FunctionBuilder()
        .ins(copy(reg(RAX), const(0)))
        .cbranch("join", reg(ZF, 1))
        .ins(copy(reg(RAX), const(1)))
        .label("join")
        .ins(copy(reg(RCX), reg(RAX)))
        .ret()
    )
    function, _ = normalize_with_observation(builder)
    control, _ = _reach(function, 3, control=True)
    assert _reaches_flag(control)


def test_conditional_move_reaches_its_condition_with_control():
    builder = FunctionBuilder().ins(*fidelity._cmov_fixed()).ins(copy(reg(RCX), reg(RAX))).ret()
    function, _ = normalize_with_observation(builder)
    data, _ = _reach(function, 1, control=False)
    control, _ = _reach(function, 1, control=True)
    assert not _reaches_flag(data) and _reaches_flag(control)


def test_infinite_loop_body_still_gets_control_dependence():
    """top: RAX = RAX + 1; if (ZF) goto top; (no exit from the loop on one side)."""
    builder = (
        FunctionBuilder()
        .label("top")
        .ins(op("INT_ADD", [reg(RAX), const(1)], reg(RAX)))
        .cbranch("top", reg(ZF, 1))
        .ret()
    )
    function, _ = normalize_with_observation(builder)
    assert function.control_dependences


def test_data_only_default_is_unchanged_for_existing_queries():
    function, _ = normalize_with_observation(_if_else())
    node = operation_node_at(function, 4)
    default = BackwardSliceQuery().run(function, node)
    explicit = BackwardSliceQuery().run(function, node, include_control=False)
    assert default == explicit


@pytest.mark.parametrize("chunk", range(4))
def test_branch_flips_only_change_control_dependent_operations(chunk):
    violations = []
    for seed in range(chunk * 75, (chunk + 1) * 75):
        builder = fidelity._random_function(random.Random(70_000 + seed))
        function, observation = normalize_with_observation(builder)
        violations += [
            (seed, item)
            for item in check_control(
                function, observation, seeds=range(4),
                register_pools=fidelity._inputs_with_bounded_loop,
            )
        ]
    assert violations == [], violations[:3]


def test_conditional_jump_out_of_the_function_controls_the_fallthrough():
    """if (ZF) goto elsewhere (outside the function); RAX = 1; RCX = RAX."""
    from synthetic import CODE_BASE

    builder = (
        FunctionBuilder()
        .ins(copy(reg(RAX), const(0)))
        .label("dummy")
        .ins(copy(reg(RAX), const(1)))
        .ins(copy(reg(RCX), reg(RAX)))
        .ret()
    )
    # make instruction 0 a conditional jump to an address outside the function
    from synthetic import RAM, _flow, ram
    raw = builder.to_json()
    first = raw["instructions"][0]
    outside = CODE_BASE + 0x900
    first["operations"] = [{
        "ordinal": 0, "opcode": "CBRANCH",
        "inputs": [ram(outside), reg(ZF, 1)], "output_present": False, "output": None,
    }]
    first["flow_targets"] = [{"space_id": RAM, "byte_offset": outside}]
    first["flow_type"] = _flow(is_flow=True, has_fallthrough=True, is_jump=True, is_conditional=True)
    builder.to_json = lambda raw=raw: raw
    function, _ = normalize_with_observation(builder)
    control, _ = _reach(function, 2, control=True)
    assert _reaches_flag(control)
