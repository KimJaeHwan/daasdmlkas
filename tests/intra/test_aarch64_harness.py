"""ARM64 Stage 1a: the synthetic harness builds AArch64 (AARCH64:LE:64:v8A)
functions as Ghidra 12.0.4 lifts them (checked against exported Bundles and
AARCH64base.sinc), so Stage 2/3 changes get AArch64 tests beside x86 ones.

- ``bl t``: INT_ADD x30 = inst_start, 4; CALL t
- ``blr xN``: COPY pc = xN; INT_ADD x30 = inst_start, 4; CALLIND pc
- ``ret`` / ``ret xN``: COPY pc = x30 / xN; RETURN pc
- ``b t`` to another function: a BRANCH Ghidra flags as a call (tail)
"""

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))

from synthetic import (
    AARCH64, CODE_BASE, PC, SP, X0, X1, X30, ZR,
    FunctionBuilder, analyze_program, analyze_summaries, boundary, const, copy, normalize, reg,
)
from tdo_v2.may_alias import stack_object_of

MAIN, SOURCE, SINK, OPAQUE = CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xA00, CODE_BASE + 0xC00
NAMES = {SOURCE: "source", SINK: "sink", OPAQUE: "opaque"}
PROVIDER = boundary({"source": 8}, {"sink": 8}, arch=AARCH64)


def _a64(entry=MAIN):
    return FunctionBuilder(entry=entry, arch=AARCH64)


def _ops(builder):
    return [[(op["opcode"], op["output"], op["inputs"]) for op in row["operations"]]
            for row in builder.to_json()["instructions"]]


def _reg(offset):
    return reg(offset, 8)


def test_bl_writes_the_link_register_then_calls():
    (bl, ret) = _ops(_a64().call(SOURCE).ret())
    assert bl == [("INT_ADD", _reg(X30), [const(MAIN, 8), const(4, 8)]),
                  ("CALL", None, [{"kind_code": bl[1][2][0]["kind_code"], "space_id": 1, "byte_offset": SOURCE,
                                   "byte_size": 8}])]
    assert ret == [("COPY", _reg(PC), [_reg(X30)]), ("RETURN", None, [_reg(PC)])]


def test_blr_takes_its_target_before_the_link_write():
    (blr, ret) = _ops(_a64().call_indirect(X30).ret(via=X1))
    assert [row[0] for row in blr] == ["COPY", "INT_ADD", "CALLIND"]
    assert blr[0] == ("COPY", _reg(PC), [_reg(X30)])
    assert blr[2] == ("CALLIND", None, [_reg(PC)])
    assert ret == [("COPY", _reg(PC), [_reg(X1)]), ("RETURN", None, [_reg(PC)])]


def test_the_link_is_inst_start_plus_four_so_the_stride_must_be_four():
    with pytest.raises(ValueError):
        FunctionBuilder(entry=MAIN, arch=AARCH64, stride=8).call(SOURCE)


def test_no_push_or_pop_on_aarch64():
    with pytest.raises(ValueError):
        _a64().push(X0)
    with pytest.raises(ValueError):
        _a64().pop(X0)


def test_an_aarch64_function_normalizes_and_blr_x30_reads_the_old_link():
    """``blr x30`` calls the x30 the function received, not the link it writes."""
    from tdo_v2.memory_contracts import MemoryDefinitionKind

    function = normalize(_a64().ins(copy(_reg(X1), const(7, 8))).call_indirect(X30).ret())
    ssa = function.memory_ssa
    (target,) = [index for index, action in enumerate(ssa.actions)
                 if action.operation_key.endswith(":0:COPY") and int(action.operation_key.split(":")[1], 16) == MAIN + 4]
    (read,) = [read for read in ssa.reads if read.action_id == target]
    ((definition,),) = [fragment.definition_ids for fragment in read.fragments]
    assert ssa.definitions[definition].kind is MemoryDefinitionKind.ENTRY


def test_no_stack_pointer_is_identified_on_aarch64_yet():
    """Pin of today's behaviour (Stage 2 changes it): the stack object is
    found from a push-call / pop-return shape, which AArch64 has none of."""
    from synthetic import summary_inputs

    (evidence,) = summary_inputs([_a64().sub_rsp(0x20).call(OPAQUE).add_rsp(0x20).ret()], image=False).evidences
    assert stack_object_of(evidence.unit.scopes, evidence.unit.observation) is None


@pytest.mark.parametrize("engine", ("summary", "legacy"))
def test_the_arm64_p0_finding_is_incomplete(engine):
    """``bl source; b sink`` with the source's result left in x0 (the ARM64 P0
    finding): never complete with no origin (Stage 0.1 R1a)."""
    main = _a64().call(SOURCE).tail_call(SINK)
    source = _a64(SOURCE).ins(copy(_reg(X0), const(7, 8))).ret()
    bodies = {"main": main, "source": source, "sink": _a64(SINK).ret()}
    if engine == "legacy":
        roots = [root for (name, label), root in analyze_program(bodies, PROVIDER).items()
                 if name == "main" and label == "sink.arg0"]
    else:
        run = analyze_summaries(list(bodies.values()), PROVIDER, names=NAMES)
        roots = [root for root in run.roots if root.function_byte_offset == MAIN and root.label == "sink.arg0"]
    assert roots
    assert all("source.ret" in root.reached_origin_labels or not root.is_effectively_complete for root in roots)


def test_a_conditional_branch_uses_a_flag_register():
    """``b.eq`` reads ZR (one byte) -- the harness's cbranch takes any varnode."""
    function = normalize(_a64().cbranch("out", reg(ZR, 1)).ins(copy(_reg(X0), const(1, 8))).label("out").ret())
    assert function.memory_ssa is not None


def test_the_aarch64_boundary_fixture_uses_x0():
    from tdo_v2.boundary import BoundaryKind

    rules = PROVIDER._rules
    assert {rule.language_id for rule in rules} == {AARCH64.language_id}
    assert {(rule.kind, rule.physical_state[0].byte_offset) for rule in rules} == {
        (BoundaryKind.SOURCE, X0), (BoundaryKind.SINK, X0)}


# -- tools (Stage 1.2): no machine is read as x86 ------------------------------

def _generation(tmp_path, head: bytes):
    import json

    (tmp_path / "original.bin").write_bytes(head + bytes(0x400 - len(head)))
    (tmp_path / "manifest.json").write_text(json.dumps(
        {"original_member_id": "o", "members": [{"id": "o", "path": "original.bin"}]}), encoding="utf-8")
    return tmp_path


def _elf(machine: int) -> bytes:
    return b"\x7fELF" + bytes([2, 1]) + bytes(12) + machine.to_bytes(2, "little")


def _pe(machine: int) -> bytes:
    head = bytearray(0x100)
    head[:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    head[0x80:0x84] = b"PE\0\0"
    head[0x84:0x86] = machine.to_bytes(2, "little")
    return bytes(head)


@pytest.mark.parametrize("head,abi", [(_elf(0xB7), "aapcs64"), (_elf(0x3E), "sysv64"), (_elf(0x03), "x86-32"),
                                      (_pe(0xAA64), "aapcs64"), (_pe(0x8664), "win64"), (_pe(0x14C), "x86-32")])
def test_the_harness_table_follows_the_machine(tmp_path, head, abi):
    import run_dfbench

    assert run_dfbench.abi_of(_generation(tmp_path, head)) == abi


@pytest.mark.parametrize("head", [_elf(0x28), _pe(0x1C4)])   # 32-bit ARM ELF / PE
def test_an_unknown_machine_is_refused(tmp_path, head):
    import run_dfbench

    with pytest.raises(ValueError):
        run_dfbench.abi_of(_generation(tmp_path, head))


def test_the_aapcs64_harness_table_uses_x0():
    import run_dfbench

    rules = run_dfbench.boundary_provider(False, "aapcs64")._rules
    assert {rule.language_id for rule in rules} == {AARCH64.language_id}
    assert {rule.physical_state[0].byte_offset for rule in rules} == {X0}


def test_the_oracles_register_table_is_per_language():
    from harness_isa import isa_of

    assert isa_of("AARCH64:LE:64:v8A")["sp"] == (SP, 8)
    assert isa_of("x86:LE:64:default")["sp"] == (0x20, 8)
    with pytest.raises(ValueError):
        isa_of("ARM:LE:32:v8")


# -- the oracle follows a link-register return (Astra 1a r1 P2) -----------------

def _observations(*builders):
    from synthetic import program_units

    return {(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset): unit.observation
            for unit in program_units(*builders)}


def _run_main(callee):
    from pcode_interpreter import Interpreter

    program = _observations(_a64().call(SOURCE).ins(copy(_reg(X0), const(99, 8))).ret(), callee)
    (main_key,) = [key for key in program if key[1] == MAIN]
    observation = program.pop(main_key)
    return Interpreter(observation, constant_space=0, seed=1, program=program).run()


def test_the_oracle_returns_to_the_continuation_through_x30():
    assert _run_main(_a64(SOURCE).ins(copy(_reg(X1), const(5, 8))).ret()).completed


def test_the_oracle_refuses_a_return_elsewhere():
    """callee: x1 = 0xdead; ret x1 -- it does not return to the call's
    continuation: the oracle must not resume there."""
    from pcode_interpreter import Unsupported

    with pytest.raises(Unsupported):
        _run_main(_a64(SOURCE).ins(copy(_reg(X1), const(0xDEAD, 8))).ret(via=X1))


def test_the_oracle_refuses_a_return_through_an_overwritten_link():
    from pcode_interpreter import Unsupported

    with pytest.raises(Unsupported):
        _run_main(_a64(SOURCE).ins(copy(_reg(X30), const(0x2000, 8))).ret())


def test_the_oracle_refuses_an_x86_return_through_a_damaged_slot():
    """callee: [rsp] = 0xdead; ret -- a push call's continuation is the pushed
    slot; the oracle never resumes at the caller's fallthrough by default
    (Astra r4 P2: refusal is not validation)."""
    from pcode_interpreter import Interpreter, Unsupported
    from synthetic import RSP, store

    callee = FunctionBuilder(entry=SOURCE).ins(store(_reg(RSP), const(0xDEAD, 8))).ret()
    good = FunctionBuilder(entry=SOURCE).ins(copy(_reg(X1), const(5, 8))).ret()
    for body, refused in ((callee, True), (good, False)):
        program = _observations(FunctionBuilder(entry=MAIN).call(SOURCE).ins(copy(_reg(X0), const(9, 8))).ret(), body)
        (main_key,) = [key for key in program if key[1] == MAIN]
        observation = program.pop(main_key)
        interpreter = Interpreter(observation, constant_space=0, seed=1, program=program)
        if refused:
            with pytest.raises(Unsupported):
                interpreter.run()
        else:
            assert interpreter.run().completed
