"""ARM64 Stage 2b: return relations and continuation certificates (docs 25.88,
.census6/design_arm64_s2_r5.md sections 3-5, r6). Observational: no analysis
reads them yet."""

import pytest

from synthetic import (
    AARCH64, CODE_BASE, RAX, RSP, X0, X1, X29, X30, X64, ZF, FunctionBuilder, _Instruction, add, const, copy,
    op, program_units, ram, reg, register_evidence, store,
)
from tdo_v2.call_seeds import _operation_key
from tdo_v2.interprocedural import analyze_units
from tdo_v2.return_relations import PAC_SPEC_12_0_4, program_certificates

MAIN, CALLEE, OTHER, OPAQUE = CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xA00, CODE_BASE + 0xC00
NOP, BTI_C, PACIASP = 0xD503201F, 0xD503245F, 0xD503233F


def _reg(offset):
    return reg(offset, 8)


def _certs(*builders, words=None, pac=PAC_SPEC_12_0_4, readable=True, registers=None, resolved=None, **options):
    """``resolved``: operation key -> callee entry, a resolution the caller
    supplies (as a forward proof would) where the engine has none."""
    arch = builders[0].arch
    units = program_units(*builders, registers=registers if registers is not None else register_evidence(arch))
    results = analyze_units(units, **options)
    functions = {}
    for key, item in results.items():
        targets = dict(item.calls)
        if resolved:
            for row in item.unit.observation.instructions:
                for index, operation in enumerate(row.operations):
                    site = _operation_key(row.address, index, operation.opcode)
                    if site in resolved:
                        entry = resolved[site]
                        targets[site] = next(other for other in results if int(other.split(":")[1], 16) == entry)
        functions[key] = (item.normalized, item.unit.observation, item.unit.scopes, targets, item.summary,
                          item.inherited_assumptions)
    words = dict(words or {})

    def reader(address, size):
        if not readable:
            return None
        return words.get(address, NOP).to_bytes(4, "little")

    return program_certificates(functions, code_reader=reader, pac_spec=pac)


def _of(certificates, entry=MAIN):
    (found,) = [certificate for key, certificate in certificates.items() if int(key.split(":")[1], 16) == entry]
    return found


def _a64(entry=MAIN):
    return FunctionBuilder(entry=entry, arch=AARCH64)


def _leaf(entry=CALLEE):
    return _a64(entry).ins(copy(_reg(X0), const(1, 8))).ret()


# -- AArch64 -------------------------------------------------------------------------

def test_a_leaf_returns_through_its_entry_x30():
    certificate = _of(_certs(_leaf(MAIN)))
    assert certificate.status == "proven" and certificate.closed
    assert [(row.kind, row.proven) for row in certificate.exits] == [("return", True)]


def test_save_call_restore_return_is_proven():
    main = _a64().stp_pre(X29, X30, -0x20).call(CALLEE).ldp_post(X29, X30, 0x20).ret()
    certificates = _certs(main, _leaf())
    assert _of(certificates).status == "proven", _of(certificates)


def test_an_overwritten_link_is_not_proven():
    main = _a64().stp_pre(X29, X30, -0x20).call(CALLEE).ldp_post(X29, X30, 0x20).ins(copy(_reg(X30), _reg(X1))).ret()
    certificate = _of(_certs(main, _leaf()))
    assert certificate.status == "unknown" and not certificate.exits[0].proven


def test_a_restore_on_one_path_only_is_not_proven():
    main = (_a64().stp_pre(X29, X30, -0x20).call(CALLEE).cbranch("skip", reg(ZF, 1))
            .ldp_post(X29, X30, 0x20).label("skip").ret())
    assert _of(_certs(main, _leaf())).status == "unknown"


@pytest.mark.parametrize("source,proven", [(X30, True), (X0, False)])
def test_ret_through_another_register(source, proven):
    main = _a64().ins(copy(_reg(X1), _reg(source))).ret(via=X1)
    assert (_of(_certs(main)).status == "proven") is proven


def test_a_tail_jump_composes_with_its_proven_target():
    main = _a64().tail_call(CALLEE)
    assert _of(_certs(main, _leaf())).status == "proven"


def test_a_tail_jump_with_a_replaced_link_proves_nothing_for_the_jumper():
    """F: x30 = BAD; b G -- G returns to ITS entry x30, which is not F's (Astra r4)."""
    main = _a64().ins(copy(_reg(X30), const(0x2000, 8))).tail_call(CALLEE)
    certificate = _of(_certs(main, _leaf()))
    assert certificate.status == "unknown" and not certificate.exits[0].proven


def test_an_opaque_call_leaves_the_function_unclosed():
    main = _a64().stp_pre(X29, X30, -0x20).call(OPAQUE).ldp_post(X29, X30, 0x20).ret()
    certificate = _of(_certs(main))
    assert certificate.status == "unknown" and not certificate.closed
    assert any(culprit.endswith(":CALL") for culprit in certificate.culprits)


def test_an_unresolved_indirect_branch_leaves_it_unclosed():
    main = _a64().ins(op("BRANCHIND", [_reg(X0)])).ret()
    assert not _of(_certs(main)).closed


@pytest.mark.parametrize("ending", ["ret", "loop"])
def test_a_listed_indirect_target_set_is_not_exhaustive(ending):
    """br x0 with one listed local target: x0 may hold any other value
    (Astra r2 P1) -- never CLOSED, whether the listed target returns or loops."""
    main = _a64()
    main._rows.append(_Instruction([op("BRANCHIND", [_reg(X0)])], "return"))
    main = main.ret() if ending == "ret" else main.label("loop").ins(copy(_reg(X1), const(1, 8))).branch("loop")
    raw = main.to_json

    def listed():
        data = raw()
        first = data["instructions"][0]
        first["flow_type"] = {key: key in ("is_flow", "is_jump", "is_computed", "is_unconditional")
                              for key in first["flow_type"]}
        first["flow_targets"] = [data["instructions"][1]["address"]]
        return data

    main.to_json = listed
    certificate = _of(_certs(main))
    assert certificate.status == "unknown" and not certificate.closed
    assert any(culprit.endswith(":BRANCHIND") for culprit in certificate.culprits), certificate


@pytest.mark.parametrize("ending", ["ret", "loop"])
def test_an_extra_reported_successor_outside_the_function_uncloses_it(ending):
    """b L whose reported targets also name unobserved FAR (Astra r3 P1)."""
    main = _a64().branch("there").label("there")
    main = main.ret() if ending == "ret" else main.label("loop").ins(copy(_reg(X1), const(1, 8))).branch("loop")
    raw = main.to_json

    def extra():
        data = raw()
        first = data["instructions"][0]
        first["flow_targets"] = sorted(first["flow_targets"] + [{"space_id": first["address"]["space_id"],
                                                                 "byte_offset": OTHER}],
                                       key=lambda item: (item["space_id"], item["byte_offset"]))
        return data

    main.to_json = extra
    certificate = _of(_certs(main))
    assert certificate.status == "unknown" and not certificate.closed
    assert any(culprit.startswith("unclassified-successor:") for culprit in certificate.culprits), certificate


def _patched(builder, index, flow=None, **fields):
    """Export ``builder`` with instruction ``index`` changed: ``flow`` -- the
    flow flags set (all others cleared); ``fields`` -- row fields (callables
    get the exported data)."""
    raw = builder.to_json

    def changed():
        data = raw()
        row = data["instructions"][index]
        if flow is not None:
            row["flow_type"] = {key: key in flow for key in row["flow_type"]}
        for name, value in fields.items():
            row[name] = value(data) if callable(value) else value
        return data

    builder.to_json = changed
    return builder


def _with(data, index, *addresses):
    space = data["instructions"][0]["address"]["space_id"]
    return sorted(data["instructions"][index]["flow_targets"]
                  + [{"space_id": space, "byte_offset": address} for address in addresses],
                  key=lambda item: (item["space_id"], item["byte_offset"]))


JUMP = ("is_flow", "is_jump", "is_unconditional")


def _unclosed(certificate, prefix):
    assert certificate.status == "unknown" and not certificate.closed, certificate
    assert any(culprit.startswith(prefix) for culprit in certificate.culprits) \
        or any(row.kind == "unresolved" for row in certificate.exits), certificate


def _conditional_tail(builder, target=CALLEE):
    builder._labels["callee"] = (target - builder.entry) // builder.stride
    return builder.cbranch("callee", reg(ZF, 1))


@pytest.mark.parametrize("opcode", ["CALL", "CALLIND"])
@pytest.mark.parametrize("flag", ["is_call", "is_jump"])
def test_s1_unmapped_call_continuation_is_not_a_legacy_tail(opcode, flag):
    from test_call_fallthrough_contract import Patched, _exit
    from tdo_v2._scope_contracts import CONTINUATION_BOUNDARY

    site = f"1:{MAIN:x}:0:{opcode}"
    for sealed in (False, True):
        builder = (Patched(entry=MAIN, arch=AARCH64,
                           exits=[_exit(MAIN, MAIN + 4, CONTINUATION_BOUNDARY, None)])
                   if sealed else _a64())
        main = builder.tail_call(CALLEE)
        main._rows[0].ops = [op(opcode, [ram(CALLEE) if opcode == "CALL" else _reg(X0)])]
        _patched(main, 0, flow=("is_flow", flag, "is_terminal", "is_unconditional"))
        known = _of(_certs(main, _leaf(), resolved={site: CALLEE}))
        if not sealed:
            assert known.status == "proven" and known.exits[0].kind == "tail"
            continue
        assert known.status == "unknown" and not known.closed
        assert [(row.kind, row.reason) for row in known.exits] == [("unresolved", "unmapped-call-continuation")]
        assert f"call:{site}" in known.dependencies
        missing = _of(_certs(main))
        assert missing.status == "unknown" and missing.exits[0].kind == "unresolved"
        loop = _a64(CALLEE).label("loop").ins(copy(_reg(X1), const(1))).branch("loop")
        nonreturning = _of(_certs(main, loop, resolved={site: CALLEE}))
        assert nonreturning.status == "noreturn" and nonreturning.exits == ()
        wrong = _of(_certs(main, _a64(OTHER).label("loop").ins(copy(_reg(X1), const(1))).branch("loop"),
                           resolved={site: OTHER}))
        assert wrong.status == "unknown" and wrong.exits[0].kind == "unresolved"


@pytest.mark.parametrize("flag", ["is_call", "is_jump"])
def test_a_conditional_tail_keeps_both_exits_and_callee_dependencies(flag):
    main = _conditional_tail(_a64()).ret()
    _patched(main, 0, flow=("is_flow", flag, "is_conditional", "has_fallthrough"),
             flow_targets=lambda data: _with(data, 0, MAIN + 4))
    certificates = _certs(main, _leaf())
    certificate = _of(certificates)
    assert certificate.status == "proven", certificate
    assert [(row.kind, row.proven) for row in certificate.exits] == [("tail", True), ("return", True)]
    tail = certificate.exits[0]
    assert tail.key == f"1:{MAIN:x}:0:CBRANCH"
    assert tail.dependencies == _of(certificates, CALLEE).dependencies
    assert f"tail:{tail.key}" in certificate.dependencies


@pytest.mark.parametrize("target", ["returning", "missing", "recursive", "noreturn"])
def test_a_conditional_tails_only_exit_is_checked_when_the_fallthrough_loops(target):
    main = _conditional_tail(_a64()).label("loop").ins(copy(_reg(X1), const(1))).branch("loop")
    functions = [main]
    if target == "returning":
        functions.append(_leaf())
    elif target == "recursive":
        functions.append(_a64(CALLEE).tail_call(MAIN))
    elif target == "noreturn":
        functions.append(_a64(CALLEE).label("loop").ins(copy(_reg(X1), const(1))).branch("loop"))
    certificate = _of(_certs(*functions))
    expected = {"returning": "proven", "missing": "unknown", "recursive": "unknown", "noreturn": "noreturn"}
    assert certificate.status == expected[target], certificate
    assert [row.kind for row in certificate.exits] == ([] if target == "noreturn" else ["tail"])


def test_a_conditional_tails_link_must_be_intact_before_transfer_even_if_fallthrough_restores_it():
    main = _a64().ins(copy(_reg(X1), _reg(X30))).ins(copy(_reg(X30), const(0x2000)))
    _conditional_tail(main).ins(copy(_reg(X30), _reg(X1))).ret()
    certificate = _of(_certs(main, _leaf()))
    assert certificate.status == "unknown", certificate
    assert [(row.kind, row.proven) for row in certificate.exits] == [("tail", False), ("return", True)]


def test_a_conditional_tail_rejects_a_certificate_for_a_different_callee():
    main = _conditional_tail(_a64()).ret()
    key = f"1:{MAIN:x}:0:CBRANCH"
    certificate = _of(_certs(main, _leaf(), _leaf(OTHER), resolved={key: OTHER}))
    assert not certificate.closed and certificate.status == "unknown"
    assert f"uncertified-call-target:{key}" in certificate.culprits
    assert certificate.exits[0].key == key and not certificate.exits[0].proven


def test_x86_conditional_tail_keeps_the_return_link_limitation():
    certificate = _of(_certs(_conditional_tail(FunctionBuilder(entry=MAIN)).ret(),
                             FunctionBuilder(entry=CALLEE).ret()))
    assert certificate.status == "unknown"
    assert certificate.exits[0].reason == "x86-tail-not-in-2b"


def test_a_split_tail_uses_its_own_ordinal_and_the_other_dangling_path_prevents_closure():
    main = _a64()
    skip = op("CBRANCH", [const(2), reg(ZF, 1)])
    main._rows.append(_Instruction([skip, op("BRANCH", [ram(CALLEE)]), copy(_reg(X1), const(1))], "return"))
    _patched(main, 0, flow=JUMP, flow_targets=lambda data: _with(data, 0, CALLEE))
    certificate = _of(_certs(main, _leaf()))
    assert certificate.status == "unknown" and not certificate.closed, certificate
    assert [(row.kind, row.key.split(":")[-2:]) for row in certificate.exits] == [
        ("tail", ["1", "BRANCH"]), ("unresolved", ["2", "COPY"])]


@pytest.mark.parametrize("target,expected", [(None, "unknown"), (CALLEE, "proven"), (OTHER, "unknown")])
def test_an_indirect_tail_needs_an_independent_resolution_covering_the_exported_target(target, expected):
    main = _a64().ins(copy(_reg(X0), const(CALLEE))).jump_indirect(_reg(X0))
    _patched(main, 1, flow_targets=lambda data: _with(data, 1, CALLEE))
    key = f"1:{MAIN + 4:x}:0:BRANCHIND"
    certificate = _of(_certs(main, _leaf(), _leaf(OTHER), resolved={key: target} if target else {}))
    assert certificate.status == expected, certificate
    assert certificate.exits[0].key == key and certificate.exits[0].kind == "tail"


@pytest.mark.parametrize("shape", ["call", "tail"])
def test_a_call_with_an_extra_reported_target_is_not_certified(shape):
    """Astra r4 P1-1: the certificate covers the resolved callee only."""
    main = _a64().stp_pre(X29, X30, -0x20).call(CALLEE).ldp_post(X29, X30, 0x20).ret() if shape == "call" \
        else _a64().tail_call(CALLEE)
    index = 1 if shape == "call" else 0
    _patched(main, index, flow_targets=lambda data: _with(data, index, OTHER))
    _unclosed(_of(_certs(main, _leaf())), "uncertified-call-target:")


@pytest.mark.parametrize("shape", ["call", "tail-leaf", "tail-loop"])
def test_an_indirect_target_must_be_the_certified_callee(shape):
    """Astra r5 P1: the resolution certifies CALLEE, the export names OTHER."""
    if shape == "call":
        main = (_a64().stp_pre(X29, X30, -0x20).ins(copy(_reg(X0), const(CALLEE, 8)))
                .call_indirect(X0).ldp_post(X29, X30, 0x20).ret())
        index = 2
    else:
        main = _a64().ins(copy(_reg(X0), const(CALLEE, 8)))
        main._rows.append(_Instruction([op("CALLIND", [_reg(X0)])], "return"))
        index = 1
        _patched(main, index, flow=("is_flow", "is_call", "is_computed", "is_terminal", "is_unconditional"))
    _patched(main, index, flow_targets=lambda data: [{"space_id": data["instructions"][0]["address"]["space_id"],
                                                      "byte_offset": OTHER}])
    callee = _a64(CALLEE).label("loop").ins(copy(_reg(X1), const(1, 8))).branch("loop") if shape == "tail-loop" \
        else _leaf()
    key = f"1:{MAIN + 4 * index:x}:{2 if shape == 'call' else 0}:CALLIND"
    certificates = _certs(main, callee, resolved={key: CALLEE})
    certificate = _of(certificates)
    assert certificate.status == "unknown" and not certificate.closed, certificate
    assert f"uncertified-call-target:{key}" in certificate.culprits, certificate


@pytest.mark.parametrize("shape", ["link-elsewhere", "link-elsewhere-loop", "fallthrough-past-a-gap"])
def test_a_proven_callee_composes_only_with_the_calls_own_continuation(shape):
    """Astra r6 P1: the callee returns to ITS entry x30 -- only the call's
    relation (2a) proves that is this call's fallthrough."""
    main = _a64().stp_pre(X29, X30, -0x20).call(CALLEE)
    main = main.label("loop").ins(copy(_reg(X1), const(1, 8))).branch("loop") if shape == "link-elsewhere-loop" \
        else main.ldp_post(X29, X30, 0x20).ret()
    if shape.startswith("link-elsewhere"):
        main._rows[1].ops[0] = copy(_reg(X30), const(OTHER, 8))
    else:
        def moved(data, index, field):
            value = dict(data["instructions"][index][field])
            value["byte_offset"] += 4
            return value

        _patched(main, 1, fallthrough=lambda data: moved(data, 1, "fallthrough"))
        _patched(main, 2, address=lambda data: moved(data, 2, "address"),
                 fallthrough=lambda data: moved(data, 2, "fallthrough"))
        _patched(main, 3, address=lambda data: moved(data, 3, "address"))
    certificates = _certs(main, _leaf())
    assert _of(certificates, CALLEE).status == "proven"
    certificate = _of(certificates)
    assert certificate.status == "unknown" and not certificate.closed, certificate
    assert any(culprit.startswith("no-continuation-relation:") for culprit in certificate.culprits), certificate


@pytest.mark.parametrize("skip", ["branch", "cbranch"])
@pytest.mark.parametrize("after", ["ret", "loop"])
def test_a_push_a_branch_may_skip_proves_no_continuation(skip, after):
    """Astra r7 P1: a relative branch in the call instruction straight to the
    CALL skips the push -- the callee returns through an unrelated slot."""
    main = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(CALLEE)
    main = main.add_rsp(0x28).ret() if after == "ret" \
        else main.label("loop").ins(copy(reg(RAX), const(1))).branch("loop")
    jump = op("BRANCH", [const(3, 8)]) if skip == "branch" else op("CBRANCH", [const(3, 8), reg(ZF, 1)])
    main._rows[1].ops.insert(0, jump)
    callee = FunctionBuilder(entry=CALLEE).ins(copy(reg(RAX), const(1))).ret()
    certificates = _certs(main, callee)
    assert _of(certificates, CALLEE).status == "proven"
    certificate = _of(certificates)
    assert certificate.status == "unknown" and not certificate.closed, certificate


def test_a_return_slot_addressed_through_an_unsettled_stack_pointer_is_not_proven():
    """Astra r7 P1: the callee is `ret 8` -- it reaches the continuation, but
    the caller's SP after it is 8 higher: the caller's own ret reads entry-SP
    + 8 although the nominal span says the entry slot."""
    main = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(CALLEE).add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=CALLEE).ins(copy(reg(RAX), const(1))).ret()
    callee._rows[-1].ops[1] = add(reg(RSP), reg(RSP), const(16))
    certificates = _certs(main, callee)
    assert _of(certificates, CALLEE).status == "proven"
    certificate = _of(certificates)
    assert certificate.status == "unknown", certificate
    assert [row.reason for row in certificate.exits] == ["address-debt"], certificate


def test_a_tail_to_a_loop_with_an_extra_reported_target_is_not_noreturn():
    loop = _a64(CALLEE).label("loop").ins(copy(_reg(X1), const(1, 8))).branch("loop")
    main = _patched(_a64().tail_call(CALLEE), 0, flow_targets=lambda data: _with(data, 0, OTHER))
    certificates = _certs(main, loop)
    assert _of(certificates, CALLEE).status == "noreturn"
    _unclosed(_of(certificates), "uncertified-call-target:")


@pytest.mark.parametrize("shape", ["cbranch-register", "branch-register", "branch-no-operand"])
def test_an_unsupported_branch_operand_is_not_classified(shape):
    """Astra r4 P1-2."""
    if shape == "cbranch-register":
        main = _a64().ins(op("CBRANCH", [_reg(X0), reg(ZF, 1)])).ins(copy(_reg(X0), const(1, 8))).ret()
    else:
        main = _a64().ins(copy(_reg(X1), const(1, 8)))
        main._rows.append(_Instruction([op("BRANCH", [_reg(X0)] if shape == "branch-register" else [])], "return"))
        _patched(main, 1, flow=JUMP)
    _unclosed(_of(_certs(main)), "unsupported-branch:")


@pytest.mark.parametrize("operations", [[], [copy(_reg(X1), const(2, 8))]])
def test_a_terminal_jump_without_a_transfer_is_not_noreturn(operations):
    """Astra r4 P1-3: no fallthrough, no targets, nothing classifies where it goes."""
    main = _a64().ins(copy(_reg(X1), const(1, 8)))
    main._rows.append(_Instruction(list(operations), "return"))
    _patched(main, 1, flow=JUMP)
    _unclosed(_of(_certs(main)), "unclassified-successor:")


def test_a_present_fallthrough_disagreeing_with_its_flag_is_not_ignored():
    """Astra r4 P1-4: a local loop's branch exporting a fallthrough to FAR
    while its flag says none."""
    main = _a64().ins(copy(_reg(X1), const(1, 8))).label("loop").ins(copy(_reg(X1), const(1, 8))).branch("loop")
    _patched(main, 2, fallthrough_present=True, fallthrough=lambda data: {"space_id": data["instructions"][0]["address"]["space_id"],
                                                "byte_offset": FAR})
    _unclosed(_of(_certs(main)), "inconsistent-fallthrough:")


def test_recursion_is_unknown():
    main = _a64().stp_pre(X29, X30, -0x20).call(MAIN).ldp_post(X29, X30, 0x20).ret()
    assert _of(_certs(main)).status == "unknown"


def test_an_exit_free_absolute_self_loop_has_no_return_certificate():
    """An absolute self edge is valid control, not a return proof."""
    certificate = _of(_certs(_a64().label("loop").branch("loop")))
    assert certificate.status == "unknown"
    assert certificate.culprits == ("unclassified-successor:1:1000:0:BRANCH",)


# -- PAC (design r6 B) -------------------------------------------------------------------

def test_a_hidden_pac_instruction_leaves_the_function_unclosed():
    """paciasp ...; ret -- under ShowPAC=0 its p-code is empty, the RETURN looks
    like pc = x30: only the encoding scan sees it."""
    main = _a64().ins(copy(_reg(X0), const(1, 8))).ret()
    certificate = _of(_certs(main, words={MAIN: PACIASP}))
    assert not certificate.closed and any(culprit.startswith("pac:") for culprit in certificate.culprits)


def test_bti_is_not_pac():
    main = _a64().ins(copy(_reg(X0), const(1, 8))).ret()
    assert _of(_certs(main, words={MAIN: BTI_C})).status == "proven"


@pytest.mark.parametrize("pac,readable", [("ghidra-12.0.3", True), (PAC_SPEC_12_0_4, False)])
def test_no_pinned_table_or_no_bytes_means_unclosed(pac, readable):
    assert not _of(_certs(_leaf(MAIN), pac=pac, readable=readable)).closed


@pytest.mark.parametrize("word", [0xD503231F, 0xD503239F, 0xD503219F, 0xDAC10020, 0xDAC143E0, 0xD65F0BFF,
                                  0xD63F081F])   # paciaz, autiaz, autia1716, pacia x0,x1, xpaci, retaa, blraaz
def test_every_family_of_the_table_is_scanned(word):
    assert not _of(_certs(_leaf(MAIN), words={MAIN: word})).closed


# -- x86 (push calls; the oracle validates push returns since 2b-1) ---------------------

def test_an_x86_leaf_returns_through_the_entry_slot():
    assert _of(_certs(FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).ret())).status == "proven"


def test_an_x86_damaged_slot_is_not_proven():
    main = FunctionBuilder(entry=MAIN).ins(store(reg(RSP), const(0xDEAD))).ret()
    assert _of(_certs(main)).status == "unknown"


def test_an_x86_frame_around_a_proven_call_is_proven():
    main = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(CALLEE).add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=CALLEE).ins(copy(reg(RAX), const(1))).ret()
    assert _of(_certs(main, callee)).status == "proven", _of(_certs(main, callee))


def test_an_unmodeled_user_op_leaves_the_function_unclosed():
    main = _a64().ins(op("CALLOTHER", [const(0x55, 4)])).ret()
    certificate = _of(_certs(main))
    assert not certificate.closed and any(culprit.endswith(":CALLOTHER") for culprit in certificate.culprits)



# -- review r1 (Astra): successors, mechanism by language, dependencies, exit fields --

FAR = CODE_BASE + 0x3000


def test_a_conditional_branch_to_unobserved_code_leaves_the_function_unclosed():
    main = _a64().ins(op("CBRANCH", [ram(FAR, 8), reg(ZF, 1)])).ins(copy(_reg(X0), const(1, 8))).ret()
    certificate = _of(_certs(main))
    assert not certificate.closed and certificate.status == "unknown"
    assert any(culprit.startswith("unclassified-successor:") for culprit in certificate.culprits)


def test_a_branch_to_unobserved_code_is_never_noreturn():
    main = _a64().ins(copy(_reg(X0), const(1, 8)))
    main._rows.append(_Instruction([], "branch", "far"))
    main._labels["far"] = (FAR - MAIN) // 4
    certificate = _of(_certs(main))
    assert certificate.status == "unknown" and not certificate.closed


def test_missing_link_evidence_is_never_read_as_a_push_mechanism():
    """AArch64 with sp but no x30 row: `ldr x30, [sp]; ret` must not be judged
    against the entry-SP slot."""
    from synthetic import load
    rows = {"revision": 1, "registers": [{"name": "sp", "space_id": 2, "byte_offset": 8, "byte_size": 8}]}
    main = _a64().ins(load(_reg(X30), _reg(8))).ret()
    certificate = _of(_certs(main, registers=rows))
    assert certificate.status == "unknown" and certificate.culprits == ("no-isa-evidence",)


def test_a_named_assumption_the_normalization_used_is_a_dependency():
    main = FunctionBuilder(entry=MAIN).ins(store(const(0x4000), const(1, 8))).ret()
    with_assumption = _of(_certs(main, assume_globals_disjoint_from_stack=True))
    assert "assumption:globals-disjoint-from-stack" in with_assumption.dependencies
    assert "assumption:stack-switch-check-exceptions" in with_assumption.dependencies
    assert "assumption:globals-disjoint-from-stack" not in _of(_certs(main)).dependencies


def test_a_return_exit_carries_the_premises_it_rests_on():
    """Astra r2 P2: the proven exit names the assumption that proved it."""
    main = FunctionBuilder(entry=MAIN).ins(store(const(0x4000), const(1, 8))).ret()
    certificate = _of(_certs(main, assume_globals_disjoint_from_stack=True))
    (row,) = certificate.exits
    assert row.proven and "assumption:globals-disjoint-from-stack" in row.dependencies
    assert set(row.dependencies) == set(certificate.dependencies)


def test_a_run_synthesized_home_space_premise_reaches_the_certificate():
    """Astra 2b-P r1: `store [entry RAX], 1; ret` is PROVEN only with the home
    space private -- the certificate lists that premise (and not without it)."""
    main = FunctionBuilder(entry=MAIN).ins(store(reg(RAX), const(1, 8))).ret()
    with_home = _of(_certs(main, private_frame_above=0x28))
    assert with_home.status == "proven", with_home
    assert "assumption:win64-home-space-callee-private" in with_home.dependencies
    assert "assumption:win64-home-space-callee-private" not in _of(_certs(main, private_frame_above=0)).dependencies


def test_a_tail_inherits_its_targets_dependencies():
    certificates = _certs(_a64().tail_call(CALLEE), _leaf())
    callee = _of(certificates, CALLEE)
    main = _of(certificates)
    assert set(callee.dependencies) <= set(main.dependencies)
    assert set(main.exits[0].dependencies) == set(callee.dependencies)


def test_an_exit_records_its_sp_delta_and_witness():
    certificate = _of(_certs(FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).ret()))
    (row,) = certificate.exits
    assert row.sp_delta == 8 and row.guard == "unknown"
    assert row.witness[0].endswith(":RETURN") and any(key.endswith(":LOAD") for key in row.witness)


def test_the_oracle_reads_an_external_tails_slot_after_the_external_ran(monkeypatch):
    """A modeled external reached by a tail jump overwrites the return slot:
    its ret goes elsewhere -- never accepted (Astra r1 P2)."""
    from pcode_interpreter import Interpreter, Unsupported
    from synthetic import RCX, RSI, DATA_BASE, tmp, add
    from synthetic import REG as REGISTER_SPACE

    slot = DATA_BASE + 0x800
    wrapper = FunctionBuilder(entry=CALLEE).ins(copy(reg(RCX), reg(RSI)))
    wrapper._rows.append(_Instruction([op("BRANCHIND", [ram(slot)])], "return"))
    raw = wrapper.to_json

    def as_ghidra():
        data = raw()
        last = data["instructions"][-1]
        last["flow_type"] = {key: key in ("is_flow", "is_jump", "is_computed", "is_unconditional")
                             for key in last["flow_type"]}
        return data

    wrapper.to_json = as_ghidra
    caller = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(CALLEE).add_rsp(0x28).ret()
    units = {(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset): unit.observation
             for unit in program_units(caller, wrapper)}
    observation = units.pop((1, MAIN))

    def clobbering(self, name, key):
        stack = sum(self._byte(REGISTER_SPACE, RSP + i)[0] << (8 * i) for i in range(8))
        for i in range(8):
            self._write(key, self._order[0][0], stack + i, 1, 0)

    monkeypatch.setattr(Interpreter, "_run_external", clobbering)
    interpreter = Interpreter(observation, constant_space=0, seed=1, program=units, havoc_calls=(REGISTER_SPACE, RSP, 8),
                              externals={(1, slot): "malloc"})
    with pytest.raises(Unsupported):
        interpreter.run()


def test_inherited_labels_reach_the_certificate():
    """2b-P: model / resolution / activation labels the analysis inherited are
    a conservative function-level dependency of its certificate."""
    from tdo_v2.interprocedural import analyze_units

    results = analyze_units(program_units(_leaf(MAIN), registers=register_evidence(AARCH64)))
    (key, item), = results.items()
    functions = {key: (item.normalized, item.unit.observation, item.unit.scopes, {}, item.summary,
                       frozenset({"forward:resolved-by-fact-1"}))}
    certificate = program_certificates(functions, code_reader=lambda a, s: NOP.to_bytes(4, "little"),
                                       pac_spec=PAC_SPEC_12_0_4)[key]
    assert "inherited:forward:resolved-by-fact-1" in certificate.dependencies


# -- design r3 (.census6/design_gt_g3b567_r3.md) ------------------------------------------------


@pytest.mark.parametrize("kind", ["entry"])   # (admission refuses a local coordinate for the other kinds)
def test_an_s1_fallthrough_exit_with_a_local_coordinate_is_an_unresolved_exit(kind):
    """(R5-1; Astra r1 P1-2) S1 lists row 0's fallthrough as leaving the function
    although the next row is in this function's body (shared code): never
    ``proven, closed`` with only the local RETURN."""
    from test_call_fallthrough_contract import Patched, _exit
    from tdo_v2._scope_contracts import (CONTINUATION_BOUNDARY, CONTINUATION_FOREIGN_INTERIOR,
                                         CONTINUATION_FUNCTION_ENTRY)
    code = {"entry": CONTINUATION_FUNCTION_ENTRY, "interior": CONTINUATION_FOREIGN_INTERIOR,
            "boundary": CONTINUATION_BOUNDARY}[kind]
    function = None if kind == "boundary" else MAIN + 4
    main = Patched(entry=MAIN, arch=AARCH64, exits=[_exit(MAIN, MAIN + 4, code, function)]) \
        .ins(copy(_reg(X1), const(7))).ret()
    certificate = _of(_certs(main))
    assert certificate.status == "unknown" and not certificate.closed
    assert ("1:1000:0:COPY", "unresolved", "s1-continuation-exit") in [
        (row.key, row.kind, row.reason) for row in certificate.exits]


def test_an_s1_row_ending_in_a_call_to_a_proven_noreturn_callee_is_no_exit():
    """(R5-1, Fable r2 P2-C) a covered exact-entry ``noreturn`` callee never
    reaches the row's end: no S1 exit; a returning callee does."""
    from test_call_fallthrough_contract import Patched, _exit
    from tdo_v2._scope_contracts import CONTINUATION_FUNCTION_ENTRY

    site = f"1:{MAIN:x}:0:CALL"

    def main():
        builder = Patched(entry=MAIN, arch=AARCH64, exits=[_exit(MAIN, MAIN + 4, CONTINUATION_FUNCTION_ENTRY, MAIN + 4)])
        return builder.call(CALLEE).ret()
    loop = _a64(CALLEE).label("loop").ins(copy(_reg(X1), const(1))).branch("loop")
    nonreturning = _of(_certs(main(), loop, resolved={site: CALLEE}))
    assert not any(row.reason == "s1-continuation-exit" for row in nonreturning.exits)
    returning = _of(_certs(main(), _leaf(), resolved={site: CALLEE}))
    assert any(row.reason == "s1-continuation-exit" for row in returning.exits)


def test_mutual_tail_recursion_certificates_do_not_depend_on_the_dict_order():
    """(R5-2; Astra r1 P2) both orders give identical certificates."""
    from synthetic import register_evidence

    results = analyze_units(program_units(_a64().tail_call(CALLEE), _a64(CALLEE).tail_call(MAIN),
                                          registers=register_evidence(AARCH64)))
    functions = {key: (item.normalized, item.unit.observation, item.unit.scopes, item.calls, item.summary,
                       item.inherited_assumptions) for key, item in results.items()}
    reader = lambda address, size: NOP.to_bytes(4, "little")  # noqa: E731
    forward, backward = (program_certificates(dict(items), code_reader=reader, pac_spec=PAC_SPEC_12_0_4)
                         for items in (list(functions.items()), list(reversed(functions.items()))))
    assert forward == backward and list(forward) == list(functions)


def test_an_s1_row_ending_in_an_address_form_cbranch_reaches_its_end():
    """(R5-1, Fable r3) its fallthrough reaches the row end: the S1 exit stands."""
    from test_call_fallthrough_contract import Patched, _exit
    from tdo_v2._scope_contracts import CONTINUATION_FUNCTION_ENTRY

    main = Patched(entry=MAIN, arch=AARCH64, exits=[_exit(MAIN, MAIN + 4, CONTINUATION_FUNCTION_ENTRY, MAIN + 4)])         .cbranch("next", reg(ZF, 1)).label("next").ret()
    certificate = _of(_certs(main))
    assert any(row.reason == "s1-continuation-exit" for row in certificate.exits) and not certificate.closed


def test_an_unmapped_s1_row_whose_branch_skips_a_noreturn_call_still_records_its_exit():
    """(R5-1, Astra r3 Q3) ``CBRANCH +2; CALL noreturn`` without a fallthrough
    coordinate: the taken path reaches the row end without the call -- one
    S1 record."""
    from test_call_fallthrough_contract import Patched, _exit
    from tdo_v2._scope_contracts import CONTINUATION_BOUNDARY

    site = f"1:{MAIN:x}:1:CALL"
    main = Patched(entry=MAIN, arch=AARCH64, exits=[_exit(MAIN, MAIN + 4, CONTINUATION_BOUNDARY, None)]).tail_call(CALLEE)
    main._rows[0].ops = [op("CBRANCH", [const(2, 4), reg(ZF, 1)]), op("CALL", [ram(CALLEE)])]
    _patched(main, 0, flow=("is_flow", "is_call", "is_terminal", "is_unconditional"))
    loop = _a64(CALLEE).label("loop").ins(copy(_reg(X1), const(1))).branch("loop")
    certificate = _of(_certs(main, loop, resolved={site: CALLEE}))
    records = [(row.kind, row.reason) for row in certificate.exits]
    assert records == [("unresolved", "unmapped-call-continuation")], records



def test_an_override_rows_raw_noreturn_call_never_cuts_its_s1_exit():
    """(r5; Astra r4 P1) a flow-override row whose raw CALL targets a certified
    infinite loop, its fallthrough an S1 FUNCTION_ENTRY boundary: the
    override's behaviour is unproved -- never ``noreturn, closed``."""
    from test_call_fallthrough_contract import Patched, _exit
    from tdo_v2._scope_contracts import CONTINUATION_FUNCTION_ENTRY

    site = f"1:{MAIN:x}:0:CALL"
    main = Patched(entry=MAIN, arch=AARCH64, exits=[_exit(MAIN, MAIN + 4, CONTINUATION_FUNCTION_ENTRY, MAIN + 4)])         .call(CALLEE).label("spin").branch("spin")
    original = main.to_json

    def overridden():
        raw = original()
        raw["instructions"][0]["flow_type"] = {**raw["instructions"][0]["flow_type"], "is_override": True}
        return raw
    main.to_json = overridden
    loop = _a64(CALLEE).label("loop").ins(copy(_reg(X1), const(1))).branch("loop")
    certificate = _of(_certs(main, loop, resolved={site: CALLEE}))
    assert certificate.status != "noreturn"
    assert any(row.reason == "s1-continuation-exit" for row in certificate.exits)



def test_a_terminal_override_row_is_never_a_noreturn_proof():
    """(r6; Astra r5 P1) no S1 metadata, a terminal override row with no
    fall-through and a raw CALL to a certified infinite loop: unproved."""
    site = f"1:{MAIN:x}:0:CALL"
    main = _a64().tail_call(CALLEE)
    main._rows[0].ops = [op("CALL", [ram(CALLEE)])]
    original = main.to_json

    def overridden():
        raw = original()
        raw["instructions"][0]["flow_type"] = {**raw["instructions"][0]["flow_type"], "is_override": True}
        return raw
    main.to_json = overridden
    loop = _a64(CALLEE).label("loop").ins(copy(_reg(X1), const(1))).branch("loop")
    certificate = _of(_certs(main, loop, resolved={site: CALLEE}))
    assert certificate.status == "unknown" and not certificate.closed
    assert any(culprit.startswith("flow-override:") for culprit in certificate.culprits)



def test_any_flow_override_row_is_a_culprit():
    """(r7; Astra r6 P1) a computed-call override row whose raw p-code is a
    plain COPY falling through to RET: the override's behaviour is unproved."""
    main = _a64().ins(copy(_reg(X1), const(7))).ret()
    original = main.to_json

    def overridden():
        raw = original()
        raw["instructions"][0]["flow_type"] = {**raw["instructions"][0]["flow_type"], "is_override": True}
        return raw
    main.to_json = overridden
    certificate = _of(_certs(main))
    assert certificate.status == "unknown" and not certificate.closed
    assert any(culprit.startswith("flow-override:") for culprit in certificate.culprits)
