"""ARM64 Stage 2a: CallRelation -- what a call instruction proves about its own
continuation (docs 25.87, .census6/design_arm64_s2_r5.md section 2). An
isolated producer: no analysis reads it yet."""

from pathlib import Path

import pytest

from synthetic import (
    AARCH64, CODE_BASE, PC, RAX, REG, RAM, RSP, SP, X0, X1, X29, X30, X64, FunctionBuilder, _Instruction, const, copy,
    normalize, op, program_units, ram, reg, register_evidence, store, sub,
)
from tdo_v2.call_relations import CallRelation, LinkSlot, call_relations
from tdo_v2.isa_identity import RegisterCoordinate, link_register

MAIN, CALLEE = CODE_BASE, CODE_BASE + 0x800
LINK = RegisterCoordinate("x30", REG, X30, 8)
STACK = RegisterCoordinate("sp", REG, SP, 8)


def _relations(builder, *, registers=True):
    arch = builder.arch
    units = program_units(builder, FunctionBuilder(entry=CALLEE, arch=arch).ret(),
                          registers=register_evidence(arch) if registers else None)
    (unit,) = [unit for unit in units if unit.scopes.function.entry.byte_offset == MAIN]
    return call_relations(unit.observation, unit.scopes)


def _only(relations) -> CallRelation:
    (relation,) = relations.values()
    return relation


def test_a_push_call_relation():
    relation = _only(_relations(FunctionBuilder(entry=MAIN).call(CALLEE).ret()))
    assert relation.kind == "push" and relation.delta == -8
    assert relation.link == LinkSlot(RAM, 8)
    assert relation.continuation.byte_offset == MAIN + 4
    assert (relation.relocation, relation.length) == ("instruction-relative", 4)
    assert len(relation.transient_ops) == 2 and relation.entry_ordinal == 2
    assert relation.sp == RegisterCoordinate("RSP", REG, 0x20, 8)


def test_a_bl_relation_writes_x30_and_moves_nothing():
    relation = _only(_relations(FunctionBuilder(entry=MAIN, arch=AARCH64).call(CALLEE).ret()))
    assert (relation.kind, relation.link, relation.sp, relation.delta) == ("link", LINK, STACK, 0)
    assert relation.continuation.byte_offset == MAIN + 4
    assert (relation.relocation, relation.length) == ("instruction-relative", 4)
    assert relation.transient_ops == ()          # the link write stays a persistent write
    assert relation.entry_ordinal == 1 and [key.rsplit(":", 1)[1] for key in relation.setup_ops] == ["INT_ADD"]


def test_blr_x30_takes_its_target_before_the_link_write():
    relation = _only(_relations(FunctionBuilder(entry=MAIN, arch=AARCH64).call_indirect(X30).ret()))
    assert relation.kind == "link" and relation.call_key.endswith(":CALLIND")
    assert [key.rsplit(":", 1)[1] for key in relation.setup_ops] == ["COPY", "INT_ADD"]
    assert relation.entry_ordinal == 2


def test_a_push_callind_relation():
    relation = _only(_relations(FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(CALLEE))).call_indirect(RAX)
                                .ret()))
    assert relation.kind == "push" and relation.call_key.endswith(":CALLIND") and relation.delta == -8


def test_no_relation_without_register_evidence():
    assert _relations(FunctionBuilder(entry=MAIN, arch=AARCH64).call(CALLEE).ret(), registers=False) == {}
    assert _relations(FunctionBuilder(entry=MAIN).call(CALLEE).ret(), registers=False) == {}


def test_a_push_through_another_register_is_no_stack_relation():
    """rax -= 8; [rax] = fallthrough; call -- RSP never moved (Astra)."""
    word = const(8)
    builder = _call_row(FunctionBuilder(entry=MAIN), [sub(reg(RAX), reg(RAX), word), store(reg(RAX), const(MAIN + 4)),
                                                      op("CALL", [ram(CALLEE)])]).ret()
    assert _relations(builder) == {}


def test_a_copied_constant_link_has_no_relocation_claim():
    builder = _call_row(FunctionBuilder(entry=MAIN, arch=AARCH64),
                        [copy(reg(X30), const(MAIN + 4)), op("CALL", [ram(CALLEE)])]).ret()
    assert _only(_relations(builder)).relocation == "unknown"


def _call_row(builder, ops):
    builder._rows.append(_Instruction(list(ops), "call", call_target=CALLEE))
    return builder


@pytest.mark.parametrize("ops", [
    # the written value is not the fallthrough
    [op("INT_ADD", [const(MAIN, 8), const(8, 8)], reg(X30)), op("CALL", [ram(CALLEE)])],
    # the link is not x30
    [op("INT_ADD", [const(MAIN, 8), const(4, 8)], reg(X29)), op("CALL", [ram(CALLEE)])],
    # another effect in the call instruction
    [copy(reg(X1), const(1)), op("INT_ADD", [const(MAIN, 8), const(4, 8)], reg(X30)), op("CALL", [ram(CALLEE)])],
    # a register (not constant) link value
    [copy(reg(X30), reg(X0)), op("CALL", [ram(CALLEE)])],
    # a "capture" that moves the stack pointer (Astra)
    [copy(reg(SP), reg(X0)), op("INT_ADD", [const(MAIN, 8), const(4, 8)], reg(X30)), op("CALLIND", [reg(SP)])],
    # the target captured into x30, then overwritten by the link write (Astra)
    [copy(reg(X30), reg(X0)), op("INT_ADD", [const(MAIN, 8), const(4, 8)], reg(X30)), op("CALLIND", [reg(X30)])],
    # a narrow capture
    [copy(reg(PC), reg(X0, 4)), op("INT_ADD", [const(MAIN, 8), const(4, 8)], reg(X30)), op("CALLIND", [reg(PC)])],
    # the CALLIND does not read the captured pc
    [copy(reg(PC), reg(X0)), op("INT_ADD", [const(MAIN, 8), const(4, 8)], reg(X30)), op("CALLIND", [reg(X1)])],
])
def test_the_link_recognizer_proves_only_its_exact_shape(ops):
    builder = _call_row(FunctionBuilder(entry=MAIN, arch=AARCH64), ops).ret()
    assert _relations(builder) == {}


def test_the_link_write_stays_in_the_persistent_unit():
    """W1: a link relation has no transient op; normalization keeps the bl's x30
    write as an action (its callee and the caller's later x30 reads see it)."""
    function = normalize(FunctionBuilder(entry=MAIN, arch=AARCH64).call(CALLEE).ret())
    keys = [action.operation_key for action in function.memory_ssa.actions]
    assert any(key.endswith(":0:INT_ADD") and int(key.split(":")[1], 16) == MAIN for key in keys)


def _ops_of(row):
    def v(item):
        return None if item is None else (item["kind_code"], item["space_id"], item["byte_offset"], item["byte_size"])
    return [(o["opcode"], v(o["output"]), [v(x) for x in o["inputs"]]) for o in row["operations"]]


def test_stp_ldp_helpers_lift_as_ghidra_does():
    """Operand wiring as in the exported P0/P1 AArch64 Bundles (unique offsets
    and the sp writeback order included)."""
    from synthetic import CONST, UNIQUE
    builder = (FunctionBuilder(entry=MAIN, arch=AARCH64).stp_pre(X29, X30, -0x20).call(CALLEE)
               .ldp_post(X29, X30, 0x20).ret())
    rows = builder.to_json()["instructions"]
    r = lambda offset: (reg(offset)["kind_code"], REG, offset, 8)
    u = lambda offset: (_tmp_kind(), UNIQUE, offset, 8)
    c = lambda value: (const(0)["kind_code"], CONST, value, 8)
    space = (const(0)["kind_code"], CONST, RAM, 8)
    assert _ops_of(rows[0]) == [
        ("COPY", u(0x73F00), [r(X29)]), ("COPY", u(0x74000), [r(X30)]),
        ("INT_ADD", r(SP), [r(SP), c((1 << 64) - 0x20)]),
        ("STORE", None, [space, r(SP), u(0x73F00)]),
        ("INT_ADD", u(0x74100), [r(SP), c(8)]),
        ("STORE", None, [space, u(0x74100), u(0x74000)])]
    assert _ops_of(rows[2]) == [
        ("COPY", u(0xF100), [r(SP)]), ("INT_ADD", r(SP), [r(SP), c(0x20)]),
        ("LOAD", u(0x48400), [space, u(0xF100)]), ("INT_ADD", u(0x48500), [u(0xF100), c(8)]),
        ("LOAD", u(0x48700), [space, u(0x48500)]),
        ("COPY", r(X29), [u(0x48400)]), ("COPY", r(X30), [u(0x48700)])]
    assert normalize(builder).memory_ssa is not None


def _tmp_kind():
    from synthetic import tmp
    return tmp(0)["kind_code"]


def test_the_link_register_identity():
    from synthetic import _Provider
    from tdo_v2._scope_contracts import _mint_orchestrator_capability
    from tdo_v2._scope_envelope import open_configured_extraction

    for arch, expected in ((AARCH64, LINK), (X64, None)):
        provider = _Provider([FunctionBuilder(arch=arch).ret()], registers=register_evidence(arch))
        with open_configured_extraction(provider, _mint_orchestrator_capability()) as envelope:
            assert link_register(envelope.program_result.evidence) == expected


def test_no_analysis_reads_the_relations_yet():
    """Isolation (2a): only the producer, the (itself observational) 2b
    certificates and tests name it; no analysis names either."""
    source = Path(__file__).resolve().parents[2] / "src" / "tdo_v2"
    for name, readers in (("call_relations", ["return_relations.py"]), ("return_relations", [])):
        users = sorted(path.name for path in source.rglob("*.py")
                       if name in path.read_text(encoding="utf-8") and path.name != f"{name}.py")
        assert users == readers, name


def test_a_push_projection_of_another_arity_binds_nothing(monkeypatch):
    """forward._projection_sensitive (W2 guard): a projection without exactly
    its adjust and store is treated as sensitive -- no facts."""
    from types import SimpleNamespace
    from tdo_v2 import forward, observed_call_state

    fake = SimpleNamespace(call_operation_key="1:1000:2:CALL", transient_operation_keys=("1:1000:0:INT_SUB",))
    monkeypatch.setattr(observed_call_state, "observed_call_state_projections", lambda observation: (fake,))
    observation = SimpleNamespace(instructions=())
    assert forward._projection_sensitive(observation) is True


def test_link_calls_reach_no_push_shape_consumer():
    """W3 / W4 stay unreached in 2a: an AArch64 bl has no push projection, so
    the consumers that read transient coordinates or a push program stack see
    nothing from it."""
    from tdo_v2.observed_call_state import observed_call_state_projections

    units = program_units(FunctionBuilder(entry=MAIN, arch=AARCH64).call(CALLEE).ret(),
                          FunctionBuilder(entry=CALLEE, arch=AARCH64).ret(), registers=register_evidence(AARCH64))
    assert all(observed_call_state_projections(unit.observation) == () for unit in units)


def test_a_push_in_another_register_space_is_no_stack_relation():
    """Two REGISTER spaces: RSP's evidence names space 9, the push moves
    offset 0x20 of space 2 -- the same offset and width, not the stack
    register (Astra)."""
    import json
    from synthetic import _Provider
    from tdo_v2._scope_contracts import _mint_orchestrator_capability
    from tdo_v2._scope_envelope import open_configured_extraction
    from tdo_v2._scope_raw import parse_raw_json

    class Raw(_Provider):
        def program_candidate(self):
            candidate = self._program_candidate()
            (register,) = [row for row in candidate["address_spaces"] if row["space_id"] == REG]
            candidate["address_spaces"].append(dict(register, space_id=9))
            candidate["register_evidence"] = {"revision": 1, "registers": [
                {"name": "RSP", "space_id": 9, "byte_offset": RSP, "byte_size": 8}]}
            return parse_raw_json(json.dumps(candidate))

    builder = FunctionBuilder(entry=MAIN).call(CALLEE).ret()
    with open_configured_extraction(Raw([builder, FunctionBuilder(entry=CALLEE).ret()]),
                                    _mint_orchestrator_capability()) as envelope:
        units = list(envelope.iter_scoped_functions())
    (unit,) = [unit for unit in units if unit.scopes.function.entry.byte_offset == MAIN]
    assert call_relations(unit.observation, unit.scopes) == {}


@pytest.mark.parametrize("skip", ["BRANCH", "CBRANCH"])
def test_a_push_a_branch_before_the_call_may_skip_is_no_projection(skip):
    """Astra 2b r7: a relative branch to the CALL bypasses the push -- neither
    the observed projection nor a relation states it."""
    from synthetic import ZF
    from tdo_v2.observed_call_state import observed_call_state_projections

    main = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(CALLEE).ret()
    main._rows[1].ops.insert(0, op(skip, [const(3, 8)] + ([reg(ZF, 1)] if skip == "CBRANCH" else [])))
    units = program_units(main, FunctionBuilder(entry=CALLEE).ret(), registers=register_evidence(X64))
    (unit,) = [unit for unit in units if unit.scopes.function.entry.byte_offset == MAIN]
    assert observed_call_state_projections(unit.observation) == ()
    assert call_relations(unit.observation, unit.scopes) == {}
