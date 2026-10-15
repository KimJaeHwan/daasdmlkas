"""Same-result accessors (docs 25.20 S1, named assumption same-result-functions,
off by default): two calls of an accessor model with equal inputs, the same
read-slot address, a slot value of the same class and the same accessor
state return the same result -- one atom, so accesses through both results
are one object. R007/R008's shape: p1 = Get(this); p2 = Get(this);
[p1+0x30] = A; [p1+0x34] = B; x = [p2+0x30] -- A only, B excluded."""

import json
from pathlib import Path

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBP, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy,
    load, op, operation_node_at, program_units, ram, reg, slice_from, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import ModelError, load_external_models, load_model_file

GET = CODE_BASE + 0xE00     # the accessor's import thunk
TOUCH = CODE_BASE + 0xE10   # a model call keeping memory, no preservation claim
KEEP = CODE_BASE + 0xE20    # the same, declaring the accessor's state preserved
OPAQUE = CODE_BASE + 0xF00  # no model
R12 = 0xA0
T, T2 = tmp(0x100), tmp(0x108)
FLAG = tmp(0x300, 1)
HEADER = {"format_version": 1, "kind": "declared", "id": "acc-test", "version": 1,
          "language_id": "x86:LE:64:default", "abi_tag": "win64", "stack_pointer": [RSP, 8], "stack_delta": 8,
          "preserved": [[24, 8], [40, 8], [48, 8], [56, 8], [160, 8], [168, 8], [176, 8], [184, 8]]}
SLOT = {"base": [RCX, 8], "disp": 0, "size": 8}


def _get(**changes):
    entry = {"name": "GetObj", "registers": [{"write": [RAX, 8], "from": [[RCX, 8]], "loads": [SLOT]}],
             "memory": [], "other_memory": "preserved", "observes": [[RCX, 8]],
             "same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT], "nonstack": True}}
    entry.update(changes)
    return entry


ENTRIES = [
    _get(),
    {"name": "Touch", "registers": [], "memory": [], "other_memory": "preserved", "observes": []},
    {"name": "Keep", "registers": [], "memory": [], "other_memory": "preserved", "observes": [],
     "preserves_accessor_state": ["acc-test/GetObj"]},
]


def _models(tmp_path, entries=ENTRIES):
    path = tmp_path / "acc.json"
    path.write_text(json.dumps({**HEADER, "entries": entries}), encoding="utf-8")
    return load_external_models([path], "x86:LE:64:default", "win64")


def _analyze(tmp_path, builder, on=True, entries=ENTRIES):
    image = ImageInfo("synthetic", (), (
        ImportedSymbol("CORE", "GetObj", None, (), ((1, GET),)),
        ImportedSymbol("CORE", "Touch", None, (), ((1, TOUCH),)),
        ImportedSymbol("CORE", "Keep", None, (), ((1, KEEP),)),
    ), (), ())
    results = analyze_units(program_units(builder), image_info=image, external_models=_models(tmp_path, entries),
                            assume_same_result_functions=on)
    return results["1:1000"]


def _caller(*between, second=None):
    """rbx = this; p1 = Get(this) (rbp); ``between``; p2 = Get(``second`` or
    this); [p1+0x30] = A (edi); [p1+0x34] = B (esi); r9d = [p2+0x30]."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(GET).ins(copy(reg(RBP), reg(RAX)))
    for row in between:
        row(builder)
    builder.ins(*(second or [copy(reg(RCX), reg(RBX))])).call(GET)
    builder.ins(add(T, reg(RBP), const(0x30)), store(T, reg(RDI, 4)))
    builder.ins(add(T, reg(RBP), const(0x34)), store(T, reg(RSI, 4)))
    builder.ins(add(T, reg(RAX), const(0x30)), load(reg(R9, 4), T))
    return builder.add_rsp(0x28).ret()


def _read(analyzed, builder):
    function = analyzed.normalized
    return slice_from(function, operation_node_at(function, len(builder._rows) - 3, 1))


def _verdict(tmp_path, *between, on=True, second=None):
    builder = _caller(*between, second=second)
    analyzed = _analyze(tmp_path, builder, on)
    read = _read(analyzed, builder)
    return analyzed, read.reaches(RDI, 4), read.reaches(RSI, 4), read.is_complete


def test_off_by_default_both_stores_may_reach_the_read(tmp_path):
    analyzed, a, b, complete = _verdict(tmp_path, on=False)
    assert a and b and not complete
    assert analyzed.normalized.same_result_uses == ()
    assert "same-result-functions" not in analyzed.inherited_assumptions


def test_equal_keys_make_one_object(tmp_path):
    analyzed, a, b, complete = _verdict(tmp_path)
    assert a and not b and complete
    uses = analyzed.normalized.same_result_uses
    assert len(uses) == 2 and len({atom for *_, atom in uses}) == 1
    assert "same-result-functions" in analyzed.inherited_assumptions


def _store_slot(builder):
    builder.ins(store(reg(RBX), reg(RDX)))      # [this] = rdx: another handle


def _same_bits(builder):
    builder.ins(load(T2, reg(RBX)), store(reg(RBX), T2))   # [this] = [this]: another class


def _call(target):
    return lambda builder: builder.call(target)


def _aliasing_store(builder):
    builder.ins(store(reg(RDX), reg(R8)))       # [rdx] = r8: rdx may be this -- a debt on the slot read


@pytest.mark.parametrize("between", [_store_slot, _same_bits, _aliasing_store, _call(TOUCH), _call(OPAQUE)],
                         ids=["reassigned", "same-bits", "aliasing-store", "finite-footprint-call", "opaque-call"])
def test_what_changes_the_key_keeps_both_stores(tmp_path, between):
    analyzed, a, b, _ = _verdict(tmp_path, between)
    assert a and b
    atoms = [atom for *_, atom in analyzed.normalized.same_result_uses]
    assert len(set(atoms)) == len(atoms)


def test_a_declared_preserving_call_keeps_the_state_and_is_reported(tmp_path):
    analyzed, a, b, complete = _verdict(tmp_path, _call(KEEP))
    assert a and not b and complete
    assert "accessor-state-preserved-by:external-model:acc-test/Keep@v1" in analyzed.inherited_assumptions


def test_another_slot_address_is_another_key(tmp_path):
    _, a, b, _ = _verdict(tmp_path, second=[add(reg(RCX), reg(RBX), const(8))])
    assert a and b


def test_another_input_value_is_another_key(tmp_path):
    entries = [_get(registers=[{"write": [RAX, 8], "from": [[RCX, 8], [RDX, 8]], "loads": [SLOT]}],
                    same_result={"result": [RAX, 8], "inputs": [[RDX, 8]], "reads": [SLOT], "nonstack": True}),
               *ENTRIES[1:]]
    for second_rdx, equal in ((reg(RDI), True), (reg(R12), False)):
        # rdx = rdi for the first call; rdi and r12 survive the calls
        builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX)), copy(reg(RDX), reg(RDI)))
        builder.call(GET).ins(copy(reg(RBP), reg(RAX)))
        builder.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), second_rdx)).call(GET)
        builder.ins(add(T, reg(RBP), const(0x34)), store(T, reg(RSI, 4)))
        builder.ins(add(T, reg(RAX), const(0x30)), load(reg(R9, 4), T))
        builder.add_rsp(0x28).ret()
        analyzed = _analyze(tmp_path, builder, entries=entries)
        atoms = [atom for *_, atom in analyzed.normalized.same_result_uses]
        assert len(atoms) == 2 and (len(set(atoms)) == 1) == equal
        assert _read(analyzed, builder).reaches(RSI, 4) != equal


def test_a_join_of_two_states_has_no_token(tmp_path):
    # rdx != 0: Touch (changes the state) -- the second Get sees a join
    def branch(builder):
        builder.cbranch("skip", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
        builder.call(TOUCH).label("skip")
    analyzed, a, b, _ = _verdict(tmp_path, branch)
    assert a and b
    # no state there: the second call gets no key row at all
    assert len([row for row, value in analyzed.normalized.pointer_rows if value[0] == "same_result"]) == 1


def test_a_join_of_equal_states_keeps_the_token(tmp_path):
    def branch(builder):
        builder.cbranch("skip", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
        builder.call(KEEP).label("skip")
    _, a, b, complete = _verdict(tmp_path, branch)
    assert a and not b and complete


def _looping(*body):
    """loop: p = Get(this); ``body``; rsi -= 1 while rsi != 0; then
    q = Get(this); r9d = [q+0x30]."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX)), copy(reg(RSI), reg(R8)))
    builder.label("top").ins(copy(reg(RCX), reg(RBX))).call(GET)
    for row in body:
        builder.ins(*row)
    builder.ins(op("INT_SUB", [reg(RSI), const(1)], reg(RSI)))
    builder.cbranch("top", FLAG, op("INT_NOTEQUAL", [reg(RSI), const(0)], FLAG))
    builder.ins(copy(reg(RCX), reg(RBX))).call(GET)
    builder.ins(add(T, reg(RAX), const(0x30)), load(reg(R9, 4), T))
    return builder.add_rsp(0x28).ret()


def test_calls_in_a_loop_with_an_invariant_key_share_the_atom(tmp_path):
    # the loop only reads through p: the state and the slot stay the same
    analyzed = _analyze(tmp_path, _looping([add(T, reg(RAX), const(0x30)), load(reg(RDX, 4), T)]))
    uses = analyzed.normalized.same_result_uses
    assert len(uses) == 2 and len({atom for *_, atom in uses}) == 1


def test_a_store_through_the_result_may_change_the_slot(tmp_path):
    # without accessor-result-separate (docs 25.20 S3) [p+0x30] may be the
    # slot: every later key read carries that debt
    analyzed = _analyze(tmp_path, _looping([add(T, reg(RAX), const(0x30)), store(T, reg(RDI, 4))]))
    assert analyzed.normalized.same_result_uses == ()


def test_a_call_in_a_loop_with_a_changing_slot_gets_no_atom(tmp_path):
    # each round first rewrites [this] (one static store, another value each
    # time): its class is no token, so p -- used as an address -- gets none
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX)), copy(reg(RSI), reg(R8)))
    builder.label("top").ins(store(reg(RBX), reg(RSI))).ins(copy(reg(RCX), reg(RBX))).call(GET)
    builder.ins(add(T, reg(RAX), const(0x30)), load(reg(RDX, 4), T))
    builder.ins(op("INT_SUB", [reg(RSI), const(1)], reg(RSI)))
    builder.cbranch("top", FLAG, op("INT_NOTEQUAL", [reg(RSI), const(0)], FLAG))
    builder.add_rsp(0x28).ret()
    analyzed = _analyze(tmp_path, builder)
    assert any(value[0] == "same_result" for _, value in analyzed.normalized.pointer_rows)
    assert analyzed.normalized.same_result_uses == ()


def test_without_nonstack_the_object_stays_wild(tmp_path):
    entries = [_get(same_result={"result": [RAX, 8], "inputs": [], "reads": [SLOT]}), *ENTRIES[1:]]
    builder = _caller()
    analyzed = _analyze(tmp_path, builder, entries=entries)
    uses = analyzed.normalized.same_result_uses
    assert len({atom for *_, atom in uses}) == 1
    assert analyzed.normalized.wild_objects   # the one object is wild: the frame may alias it


@pytest.mark.parametrize("change, problem", [
    ({"same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT], "write_back": True}}, "write-back"),
    ({"same_result": {"result": [RDX, 8], "inputs": [], "reads": [SLOT]}}, "result not written"),
    ({"same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT, SLOT]}}, "two slots"),
    ({"same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT], "nonstack": 1}}, "nonstack"),
    ({"preserves_accessor_state": ["GetObj"]}, "unqualified name"),
    ({"same_result": {"result": [RAX, 8], "inputs": [[RDX, 8]], "reads": [SLOT], "nonstack": True}},
     "input not read by the result row"),
    ({"registers": [{"write": [RAX, 8], "from": [[RCX, 8]]}]}, "slot not loaded by the result row"),
])
def test_an_accessor_entry_is_validated(tmp_path, change, problem):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({**HEADER, "entries": [_get(**change)]}), encoding="utf-8")
    with pytest.raises(ModelError):
        load_model_file(path)


def test_a_partial_write_of_the_slot_leaves_no_class(tmp_path):
    analyzed, a, b, _ = _verdict(tmp_path, lambda builder: builder.ins(store(reg(RBX), reg(RDX, 4))))
    assert a and b
    assert len(analyzed.normalized.same_result_uses) == 1   # the second call's slot read has two definitions


GET_B = CODE_BASE + 0xE30   # a second accessor


def _two_accessors(tmp_path, *between):
    """pa1 = GetObj(this) (rbp); pb1 = GetB(this) (rsi); ``between``;
    pa2 = GetObj(this) (rdi); pb2 = GetB(this) (r12); a load through each."""
    entries = [*ENTRIES, {**_get(), "name": "GetB"}]
    image = ImageInfo("synthetic", (), (
        ImportedSymbol("CORE", "GetObj", None, (), ((1, GET),)),
        ImportedSymbol("CORE", "Touch", None, (), ((1, TOUCH),)),
        ImportedSymbol("CORE", "Keep", None, (), ((1, KEEP),)),
        ImportedSymbol("CORE", "GetB", None, (), ((1, GET_B),)),
    ), (), ())
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX)))
    for target, keep in ((GET, RBP), (GET_B, RSI)):
        builder.ins(copy(reg(RCX), reg(RBX))).call(target).ins(copy(reg(keep), reg(RAX)))
    for row in between:
        row(builder)
    for target, keep in ((GET, RDI), (GET_B, R12)):
        builder.ins(copy(reg(RCX), reg(RBX))).call(target).ins(copy(reg(keep), reg(RAX)))
    for keep in (RBP, RSI, RDI, R12):
        builder.ins(add(T, reg(keep), const(0x30)), load(reg(R9, 4), T))
    builder.add_rsp(0x28).ret()
    results = analyze_units(program_units(builder), image_info=image, external_models=_models(tmp_path, entries),
                            assume_same_result_functions=True)
    uses = results["1:1000"].normalized.same_result_uses
    by_identity = {}
    for row, identity, _, atom in uses:
        by_identity.setdefault(identity.split("/")[1].split("@")[0], []).append(atom)
    return by_identity


def test_a_claim_for_one_accessor_does_not_keep_another(tmp_path):
    found = _two_accessors(tmp_path, _call(KEEP))
    assert len(found["GetObj"]) == 2 and len(set(found["GetObj"])) == 1
    assert len(set(found["GetB"])) == 2


def _unknown_state(builder):
    builder.cbranch("skip", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
    builder.call(TOUCH).label("skip")


def test_a_preservation_claim_after_an_unknown_state_keeps_it_unknown(tmp_path):
    # Get1; a join of two states; Keep; Get2 -- no state for Get2
    builder = _caller(_unknown_state, _call(KEEP))
    analyzed = _analyze(tmp_path, builder)
    rows = [row for row, value in analyzed.normalized.pointer_rows if value[0] == "same_result"]
    assert len(rows) == 1   # Get1 only


def test_a_once_executed_invalidating_call_starts_a_new_state(tmp_path):
    # Get1; join of two states; Touch (once): a new token -- the two Gets
    # after it share it, and differ from Get1
    found = _two_accessors(tmp_path, _unknown_state, _call(TOUCH))
    assert len(set(found["GetObj"])) == 2 and len(set(found["GetB"])) == 2
    builder = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(GET).ins(copy(reg(RBP), reg(RAX))))
    _unknown_state(builder)
    builder.call(TOUCH)
    for keep in (RSI, RDI):
        builder.ins(copy(reg(RCX), reg(RBX))).call(GET).ins(copy(reg(keep), reg(RAX)))
    for keep in (RBP, RSI, RDI):
        builder.ins(add(T, reg(keep), const(0x30)), load(reg(R9, 4), T))
    builder.add_rsp(0x28).ret()
    atoms = [atom for *_, atom in _analyze(tmp_path, builder).normalized.same_result_uses]
    assert len(atoms) == 3 and len(set(atoms)) == 2 and atoms.count(atoms[-1]) == 2


def test_the_final_check_flags_a_key_that_changed(tmp_path):
    # ``stale_reads`` recomputes each used key whole on the final state: a
    # recorded atom that differs (as a late-resolved store of the same bits
    # would make it) blocks the ~sr row -- the call falls back to its own atom
    from types import SimpleNamespace

    from tdo_v2.relative_memory import stale_reads

    builder = _caller()
    analyzed = _analyze(tmp_path, builder)
    function, observation = analyzed.normalized, analyzed.unit.observation
    pointer_rows = dict(function.pointer_rows)
    (row, _, _, atom), _ = function.same_result_uses
    reader = pointer_rows[row][2]
    effect_unit = SimpleNamespace(function_scope=function.memory_ssa.function_scope)
    for wrong, flagged in ((atom, False), (atom ^ 1, True)):
        used = {(("same_result", row, reader), 8): {wrong}}
        failed = stale_reads(
            effect_unit, observation, function.scopes.resolution_context,
            function.scopes.program.evidence.address_spaces, function.memory_ssa, used,
            translation_namespace=function.scopes.program.evidence.translation_namespace.language_id,
            once_keys=_once_keys(analyzed), pointer_rows=pointer_rows)
        assert (reader in failed) == flagged


def _once_keys(analyzed):
    from tdo_v2.pcode_blocks import build_pcode_block_graph
    from tdo_v2.relative_memory import single_execution_keys

    observation = analyzed.unit.observation
    return single_execution_keys(observation, build_pcode_block_graph(
        observation, analyzed.unit.scopes.function.entry, frozenset()))


def test_the_summary_boundary_drops_the_identity(tmp_path):
    # a function returning an accessor result: its summary states no pointer
    # value for rax (same-result atoms are activation-local), even with nonstack
    analyzed = _analyze(tmp_path, _caller())
    assert analyzed.normalized.same_result_uses
    for exit_ in analyzed.summary.exits:
        for run in exit_.runs:
            if run.span.object_id.kind.name == "REGISTER_FILE" and run.span.start == RAX:
                assert run.value is None


def test_a_preservation_claim_must_name_an_accessor(tmp_path):
    entries = [_get(), {"name": "Keep", "registers": [], "memory": [], "other_memory": "preserved",
                        "observes": [], "preserves_accessor_state": ["acc-test/Touch"]}]
    with pytest.raises(ModelError):
        _models(tmp_path, entries)


# -- the program oracle: real accessor bodies ---------------------------------

def _body(*rows):
    builder = FunctionBuilder(entry=GET)
    for row in rows:
        builder.ins(*row)
    return builder.ret()


def _oracle(tmp_path, body):
    builder = _caller()
    analyzed = _analyze(tmp_path, builder)
    (callee,) = program_units(body)
    return check_program(analyzed.normalized, analyzed.unit.observation, {(1, GET): callee.observation},
                         seeds=range(6),
                         register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                         havoc_calls=(REG, RSP, 8))


def test_the_oracle_checks_equal_results_on_a_real_getter(tmp_path):
    report = _oracle(tmp_path, _body([load(reg(RAX), reg(RCX))]))
    assert report.runs and report.same_result_checked and report.same_result_violations == []
    assert report.silent == []


def test_the_oracle_reports_a_body_breaking_the_contract(tmp_path):
    # returns a counter it increments: equal keys, different results
    body = _body([load(reg(RAX), ram(DATA_BASE))], [add(T, reg(RAX), const(8)), store(ram(DATA_BASE), T)])
    report = _oracle(tmp_path, body)
    assert report.same_result_checked and report.same_result_violations
