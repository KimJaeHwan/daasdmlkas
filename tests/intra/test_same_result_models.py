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
    NO_CALLBACKS,
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBP, RBX, RCX, RDI, RDX, REG, RIP, RSI, RSP, FunctionBuilder, add, const, copy,
    load, op, operation_node_at, program_units, ram, reg, slice_from, store, sub, tmp,
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
             "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": [[RCX, 8]],
             "same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT], "nonstack": True}}
    entry.update(changes)
    return entry


ENTRIES = [
    _get(),
    {"name": "Touch", "registers": [], "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": []},
    {"name": "Keep", "registers": [], "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": [],
     "preserves_accessor_state": ["acc-test/GetObj"]},
]


def _models(tmp_path, entries=ENTRIES):
    path = tmp_path / "acc.json"
    path.write_text(json.dumps({**HEADER, "entries": entries}), encoding="utf-8")
    return load_external_models([path], "x86:LE:64:default", "win64")


def _analyze(tmp_path, builder, on=True, entries=ENTRIES, separate=False):
    image = ImageInfo("synthetic", (), (
        ImportedSymbol("CORE", "GetObj", None, (), ((1, GET),)),
        ImportedSymbol("CORE", "Touch", None, (), ((1, TOUCH),)),
        ImportedSymbol("CORE", "Keep", None, (), ((1, KEEP),)),
    ), (), ())
    results = analyze_units(program_units(builder), image_info=image, external_models=_models(tmp_path, entries),
                            assume_same_result_functions=on, assume_accessor_result_separate=separate)
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


def _complete_but_for_pushes(analyzed, read):
    """Complete except for may-alias debt of CALL pushes only: the accessor
    result is a wild object (it may point anywhere, the frame included), so
    a push before the read -- a frame write like any other
    (``normalize._push_row``, docs 25.73) -- reaches it."""
    if read.is_complete:
        return True
    graph = analyzed.normalized.dependencies
    keys = {graph.node(node).key for node in read.result.reachable_unresolved_read_nodes}
    rows = [row for row in analyzed.normalized.may_alias_reads if any(row.operation_key in key for key in keys)]
    return bool(rows) and len(rows) == len(keys) and all(
        writer.endswith("~push") for row in rows for writer in row.writers)


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
    entries = [_get(), {"name": "Keep", "registers": [], "memory": [], **NO_CALLBACKS, "other_memory": "preserved",
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


# -- S2: write-back (docs 25.20) -------------------------------------------------

WRITE_BACK = {"write": SLOT, "from": [[RCX, 8]], "loads": [SLOT]}


def _get_written_back(**changes):
    return _get(**{"memory": [WRITE_BACK], "same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT],
                                                           "nonstack": True, "write_back": True}, **changes})


WRITTEN_BACK = [_get_written_back(), *ENTRIES[1:]]


def _three(*between):
    """p1 = Get(this) (rbp); ``between``; p2 = Get(this) (rsi); p3 = Get(this);
    [p1+0x30] = A (edi); [p2+0x34] = B (r12d); r9d = [p3+0x30]."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(GET).ins(copy(reg(RBP), reg(RAX)))
    for row in between:
        row(builder)
    builder.ins(copy(reg(RCX), reg(RBX))).call(GET).ins(copy(reg(RSI), reg(RAX)))
    builder.ins(copy(reg(RCX), reg(RBX))).call(GET)
    builder.ins(add(T, reg(RBP), const(0x30)), store(T, reg(RDI, 4)))
    builder.ins(add(T, reg(RSI), const(0x34)), store(T, reg(R12, 4)))
    builder.ins(add(T, reg(RAX), const(0x30)), load(reg(R9, 4), T))
    return builder.add_rsp(0x28).ret()


def test_a_written_back_slot_keeps_its_class(tmp_path):
    builder = _three()
    analyzed = _analyze(tmp_path, builder, entries=WRITTEN_BACK)
    atoms = [atom for *_, atom in analyzed.normalized.same_result_uses]
    assert len(atoms) == 3 and len(set(atoms)) == 1
    read = _read(analyzed, builder)
    assert read.reaches(RDI, 4) and not read.reaches(R12, 4) and read.is_complete


def test_a_write_back_under_another_key_is_an_ordinary_write(tmp_path):
    # Touch changes the state: Get2's key differs from Get1's, so Get1's
    # write-back is an ordinary (once) write for it; Get3 inherits Get2's class
    analyzed = _analyze(tmp_path, _three(_call(TOUCH)), entries=WRITTEN_BACK)
    uses = sorted(analyzed.normalized.same_result_uses)
    atoms = [atom for *_, atom in uses]
    assert len(atoms) == 3 and atoms[0] != atoms[1] and atoms[1] == atoms[2]


def test_a_write_back_in_a_loop_gives_no_class(tmp_path):
    # the slot at the call joins its entry value and the call's own write-back
    # (a cycle): no class in v1
    analyzed = _analyze(tmp_path, _looping([add(T, reg(RAX), const(0x30)), load(reg(RDX, 4), T)]),
                        entries=WRITTEN_BACK)
    assert analyzed.normalized.same_result_uses == ()


@pytest.mark.parametrize("entry, problem", [
    (_get(same_result={"result": [RAX, 8], "inputs": [], "reads": [SLOT], "write_back": True}), "no write row"),
    (_get(memory=[WRITE_BACK]), "a slot write without write_back"),
    (_get_written_back(memory=[{"write": SLOT, "from": [[RCX, 8]]}]), "the write does not load the slot"),
    (_get_written_back(
        registers=[{"write": [RAX, 8], "from": [[RCX, 8], [RDX, 8]], "loads": [SLOT]}],
        same_result={"result": [RAX, 8], "inputs": [[RDX, 8]], "reads": [SLOT], "write_back": True}),
     "the write does not read an input"),
    (_get_written_back(memory=[WRITE_BACK, {"write": {"base": [RCX, 8], "disp": 4, "size": 4}, "value": "unknown"}]),
     "an unknown write over the slot"),
    (_get_written_back(memory=[WRITE_BACK, {"write": {"base": [RCX, 8], "disp": -4, "size": 8}, "from": []}]),
     "another write overlapping the slot"),
])
def test_a_write_back_entry_is_validated(tmp_path, entry, problem):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({**HEADER, "entries": [entry]}), encoding="utf-8")
    with pytest.raises(ModelError):
        load_model_file(path)


def _resolver(entry=GET):
    """rax = [rcx]; if rax & 1 (unresolved): rax ^= 1, [rcx] = rax; ret --
    a lazy resolver writing the resolved value back."""
    builder = FunctionBuilder(entry=entry).ins(load(reg(RAX), reg(RCX)))
    builder.cbranch("done", FLAG, op("INT_AND", [reg(RAX, 1), const(1, 1)], tmp(0x310, 1)),
                    op("INT_EQUAL", [tmp(0x310, 1), const(0, 1)], FLAG))
    builder.ins(op("INT_XOR", [reg(RAX), const(1)], reg(RAX))).ins(store(reg(RCX), reg(RAX)))
    return builder.label("done").ret()


def test_the_oracle_counts_write_backs_whose_results_are_unused(tmp_path):
    # Get1's result is discarded; Get2 / Get3 inherit the class its write-back left
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(GET)
    builder.ins(copy(reg(RCX), reg(RBX))).call(GET).ins(copy(reg(RSI), reg(RAX)))
    builder.ins(copy(reg(RCX), reg(RBX))).call(GET)
    builder.ins(add(T, reg(RSI), const(0x34)), store(T, reg(R12, 4)))
    builder.ins(add(T, reg(RAX), const(0x30)), load(reg(R9, 4), T))
    builder.add_rsp(0x28).ret()
    analyzed = _analyze(tmp_path, builder, entries=WRITTEN_BACK)
    assert len(analyzed.normalized.same_result_uses) == 2
    (callee,) = program_units(_resolver())
    report = check_program(analyzed.normalized, analyzed.unit.observation, {(1, GET): callee.observation},
                           seeds=range(8),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.same_result_checked and report.same_result_violations == []
    assert report.same_result_unchecked   # Get1's write-backs, counted though its result is unused


def test_the_oracle_runs_a_write_back_resolver(tmp_path):
    builder = _three()
    analyzed = _analyze(tmp_path, builder, entries=WRITTEN_BACK)
    (callee,) = program_units(_resolver())
    report = check_program(analyzed.normalized, analyzed.unit.observation, {(1, GET): callee.observation},
                           seeds=range(8),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.same_result_checked and report.same_result_violations == []
    assert report.same_result_unchecked   # some runs start unresolved: the write-back is unchecked
    assert report.silent == []


def test_a_write_back_by_a_call_with_other_inputs_is_an_ordinary_write(tmp_path):
    # Get(this, rdi); Get(this, r12); Get(this, rdi): the second call may
    # normalize the slot to another form for its input -- the third does not
    # inherit the first call's class through it
    entries = [_get_written_back(
        registers=[{"write": [RAX, 8], "from": [[RCX, 8], [RDX, 8]], "loads": [SLOT]}],
        memory=[{"write": SLOT, "from": [[RCX, 8], [RDX, 8]], "loads": [SLOT]}],
        same_result={"result": [RAX, 8], "inputs": [[RDX, 8]], "reads": [SLOT], "nonstack": True,
                     "write_back": True}), *ENTRIES[1:]]
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX)))
    for value, keep in ((RDI, RBP), (R12, RSI), (RDI, None)):
        builder.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), reg(value))).call(GET)
        if keep is not None:
            builder.ins(copy(reg(keep), reg(RAX)))
    for base in (RBP, RSI, RAX):
        builder.ins(add(T, reg(base), const(0x30)), load(reg(R9, 4), T))
    builder.add_rsp(0x28).ret()
    atoms = [atom for *_, atom in sorted(_analyze(tmp_path, builder, entries=entries).normalized.same_result_uses)]
    assert len(atoms) == 3 and len(set(atoms)) == 3


# -- S3: accessor-result-separate (docs 25.20 D) ----------------------------------

SEPARATE = [_get_written_back(result_separate_from_reads={"extent": 0x38}), *ENTRIES[1:]]


def _r007(*after, store_at=0x30):
    """R007's shape: p1 = Get(this) (rbp); [p1+``store_at``] = A (edi);
    p2 = Get(this); [p2+0x34] = B (r12d); p3 = Get(this); ``after``;
    r9d = [p3+0x30]."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(GET).ins(copy(reg(RBP), reg(RAX)))
    builder.ins(add(T, reg(RBP), const(store_at)), store(T, reg(RDI, 4)))
    builder.ins(copy(reg(RCX), reg(RBX))).call(GET)
    builder.ins(add(T, reg(RAX), const(0x34)), store(T, reg(R12, 4)))
    builder.ins(copy(reg(RCX), reg(RBX))).call(GET)
    for row in after:
        builder.ins(*row)
    builder.ins(add(T, reg(RAX), const(0x30)), load(reg(R9, 4), T))
    return builder.add_rsp(0x28).ret()


def test_r007_with_separation_reads_a_only(tmp_path):
    builder = _r007()
    analyzed = _analyze(tmp_path, builder, entries=SEPARATE, separate=True)
    atoms = [atom for *_, atom in analyzed.normalized.same_result_uses]
    assert len(atoms) == 3 and len(set(atoms)) == 1
    read = _read(analyzed, builder)
    assert read.reaches(RDI, 4) and not read.reaches(R12, 4) and _complete_but_for_pushes(analyzed, read)
    assert {"same-result-functions", "accessor-result-separate"} <= analyzed.inherited_assumptions
    assert analyzed.normalized.accessor_separations


def test_r007_without_separation_keeps_b(tmp_path):
    builder = _r007()
    analyzed = _analyze(tmp_path, builder, entries=SEPARATE, separate=False)
    read = _read(analyzed, builder)
    assert read.reaches(RDI, 4) and read.reaches(R12, 4)
    assert analyzed.normalized.accessor_separations == ()
    assert "accessor-result-separate" not in analyzed.inherited_assumptions


def test_a_slot_of_a_call_that_may_not_run_separates_nothing(tmp_path):
    # p = Get(this); if rdx == 0: q = Get(r12), [q+0x30] read; [r12] = A;
    # x = [p+0x30] -- when Get(r12) does not run, r12 may be p+0x30
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(GET).ins(copy(reg(RBP), reg(RAX)))
    builder.cbranch("skip", FLAG, op("INT_NOTEQUAL", [reg(RDX), const(0)], FLAG))
    builder.ins(copy(reg(RCX), reg(R12))).call(GET).ins(add(T, reg(RAX), const(0x30)), load(reg(RSI, 4), T))
    builder.label("skip").ins(store(reg(R12), reg(RDI, 4)))
    builder.ins(add(T, reg(RBP), const(0x30)), load(reg(R9, 4), T))
    builder.add_rsp(0x28).ret()
    # (no write-back: Get(this)'s would put debt on Get(r12)'s slot read)
    entries = [_get(result_separate_from_reads={"extent": 0x38}), *ENTRIES[1:]]
    analyzed = _analyze(tmp_path, builder, entries=entries, separate=True)
    calls = {pair[4] for pair in analyzed.normalized.accessor_separations}
    assert len(calls) == 2   # both slots have pairs, but the store may come without Get(r12)
    read = _read(analyzed, builder)
    assert read.reaches(RDI, 4)
    (callee,) = program_units(_body([load(reg(RAX), reg(RCX))]))
    report = check_program(analyzed.normalized, analyzed.unit.observation, {(1, GET): callee.observation},
                           seeds=range(8),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000,
                                                        RDX: seed % 2},
                           havoc_calls=(REG, RSP, 8))
    assert report.silent == []


def test_a_store_outside_the_extent_is_not_separated(tmp_path):
    # [p1+0x40] lies beyond the 0x38 bytes: it may be the slot
    builder = _r007(store_at=0x40)
    analyzed = _analyze(tmp_path, builder, entries=SEPARATE, separate=True)
    assert len(analyzed.normalized.same_result_uses) == 1   # Get2's slot read carries the store's debt
    assert _read(analyzed, builder).reaches(R12, 4)


def test_a_write_beside_the_slot_still_reaches_the_result(tmp_path):
    # [this+8] = rdx after the last Get: the slot's object but not the slot's
    # bytes -- it may still be [p3+0x30]
    builder = _r007([add(T2, reg(RBX), const(8)), store(T2, reg(RDX))])
    analyzed = _analyze(tmp_path, builder, entries=SEPARATE, separate=True)
    read = _read(analyzed, builder)
    assert not read.is_complete and read.reaches(RDX)


def test_a_store_through_the_result_in_a_loop_stays_unseparated(tmp_path):
    # v1 limit: the loop's slot read waits for the store through the previous
    # round's result, whose address waits for the key -- resolved only in the
    # last stage, which the pending-write rule undoes: no key, no separation
    entries = [_get(result_separate_from_reads={"extent": 0x38}), *ENTRIES[1:]]
    analyzed = _analyze(tmp_path, _looping([add(T, reg(RAX), const(0x30)), store(T, reg(RDI, 4))]),
                        entries=entries, separate=True)
    assert analyzed.normalized.same_result_uses == () and analyzed.normalized.accessor_separations == ()


@pytest.mark.parametrize("change, problem", [
    ({"same_result": None, "result_separate_from_reads": {"extent": 0x38}}, "no same_result"),
    ({"result_separate_from_reads": {"extent": 0}}, "empty extent"),
    ({"result_separate_from_reads": {"extent": 1 << 20}}, "too large"),
    ({"result_separate_from_reads": {"extent": 8, "start": 0}}, "unknown key"),
])
def test_a_separation_entry_is_validated(tmp_path, change, problem):
    entry = _get(**change)
    if entry.get("same_result") is None:
        entry.pop("same_result")
    path = tmp_path / "t.json"
    path.write_text(json.dumps({**HEADER, "entries": [entry]}), encoding="utf-8")
    with pytest.raises(ModelError):
        load_model_file(path)


def _r007_oracle(tmp_path, body):
    builder = _r007()
    analyzed = _analyze(tmp_path, builder, entries=SEPARATE, separate=True)
    (callee,) = program_units(body)
    return check_program(analyzed.normalized, analyzed.unit.observation, {(1, GET): callee.observation},
                         seeds=range(8),
                         register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                         havoc_calls=(REG, RSP, 8))


def test_the_oracle_finds_no_separation_violation_for_a_resolver(tmp_path):
    report = _r007_oracle(tmp_path, _resolver())
    assert report.same_result_checked and report.same_result_violations == [] and report.silent == []


def test_the_oracle_reports_a_result_holding_its_own_slot(tmp_path):
    # returns the slot's own address: [result, result + 0x38) holds the slot
    report = _r007_oracle(tmp_path, _body([copy(reg(RAX), reg(RCX))]))
    assert any(item[0] == "separation" for item in report.same_result_violations)


# -- S4: accessor-private-state and verified bindings (docs 25.20 F) ---------------

from tdo_v2.summary_store import load_binding_file  # noqa: E402

INTERNAL = CODE_BASE + 0x400   # the accessor as a function of the program itself


def _bound_program(target=INTERNAL):
    """The R007 caller calling ``target``, and the resolver's body there."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(target).ins(copy(reg(RBP), reg(RAX)))
    builder.ins(add(T, reg(RBP), const(0x30)), store(T, reg(RDI, 4)))
    builder.ins(copy(reg(RCX), reg(RBX))).call(target)
    builder.ins(add(T, reg(RAX), const(0x34)), store(T, reg(R12, 4)))
    builder.ins(copy(reg(RCX), reg(RBX))).call(target)
    builder.ins(add(T, reg(RAX), const(0x30)), load(reg(R9, 4), T))
    return builder.add_rsp(0x28).ret(), _resolver(INTERNAL)


def _binding(tmp_path, units, *, sha=None, rva=None, entry=None):
    evidence = units[0].scopes.program.evidence
    model = {**HEADER, "id": "bound-test", "entries": [entry or _get_written_back(
        result_separate_from_reads={"extent": 0x38}, omits_private_writes=True)]}
    (tmp_path / "bound.json").write_text(json.dumps(model), encoding="utf-8")
    raw = {"format_version": 1, "kind": "binding", "id": "test-binding",
           "executable_sha256": sha or evidence.executable_sha256.hex(), "language_id": HEADER["language_id"],
           "abi_tag": "win64", "models": ["bound.json"],
           "bindings": [{"rva": hex(rva if rva is not None else INTERNAL - evidence.image_base.byte_offset),
                         "model": "bound-test/GetObj"}]}
    (tmp_path / "binding.json").write_text(json.dumps(raw), encoding="utf-8")
    return load_binding_file(tmp_path / "binding.json")


def _analyze_bound(tmp_path, private=True, **binding):
    caller, body = _bound_program()
    units = program_units(caller, body)
    results = analyze_units(units, model_bindings=(_binding(tmp_path, units, **binding),),
                            external_models=_models(tmp_path), assume_same_result_functions=True,
                            assume_accessor_result_separate=True, assume_accessor_private_state=private)
    return results, caller


def test_a_bound_function_is_cut_and_its_callers_take_the_model(tmp_path):
    results, caller = _analyze_bound(tmp_path)
    assert f"1:{INTERNAL:x}" not in results
    analyzed = results["1:1000"]
    atoms = [atom for *_, atom in analyzed.normalized.same_result_uses]
    assert len(atoms) == 3 and len(set(atoms)) == 1
    read = _read(analyzed, caller)
    assert read.reaches(RDI, 4) and not read.reaches(R12, 4) and _complete_but_for_pushes(analyzed, read)
    rva = INTERNAL - analyzed.unit.scopes.program.evidence.image_base.byte_offset
    digest = load_binding_file(tmp_path / "binding.json").digest
    assert {f"bound-model:test-binding@{rva:#x}#{digest[:12]}", "accessor-private-state", "same-result-functions",
            "accessor-result-separate"} <= analyzed.inherited_assumptions
    # per use: the binding, its digest, the rva, the binary, the model and its file
    assert len(analyzed.bound_calls) == 3
    binding_id, binding_digest, bound_rva, sha, label, _ = next(iter(analyzed.bound_calls.values()))
    assert (binding_id, binding_digest, bound_rva) == ("test-binding", digest, rva)
    assert sha == analyzed.unit.scopes.program.evidence.executable_sha256.hex()
    assert label == "external-model:bound-test/GetObj@v1"


def test_without_private_state_the_bound_body_is_analyzed(tmp_path):
    results, caller = _analyze_bound(tmp_path, private=False)
    assert f"1:{INTERNAL:x}" in results
    assert results["1:1000"].normalized.same_result_uses == ()
    (reason,) = results[f"1:{INTERNAL:x}"].refused_models.values()   # why the binding was not applied
    assert "accessor-private-state" in reason


def test_the_oracle_sees_a_bound_body_overwriting_a_kept_register(tmp_path):
    # the body makes an unknown call (the interpreter keeps the model's
    # preserved registers across it), then moves its result into rbx -- which
    # the model says is kept: the caller's read of rbx is a miss
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RDI))).call(INTERNAL)
              .ins(copy(reg(R9), reg(RBX))).add_rsp(0x28).ret())
    body = (FunctionBuilder(entry=INTERNAL).sub_rsp(0x28).call_indirect(RDX).ins(copy(reg(RBX), reg(RAX)))
            .ins(load(reg(RAX), reg(RCX))).add_rsp(0x28).ret())
    units = program_units(caller, body)
    entry = _get(omits_private_writes=True, same_result={"result": [RAX, 8], "inputs": [], "reads": [SLOT]})
    results = analyze_units(units, model_bindings=(_binding(tmp_path, units, entry=entry),),
                            external_models=_models(tmp_path), assume_same_result_functions=True,
                            assume_accessor_private_state=True)
    analyzed = results["1:1000"]
    report = check_program(analyzed.normalized, analyzed.unit.observation, {(1, INTERNAL): units[1].observation},
                           seeds=range(4),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert any(dependency.reader == "1:100c:0:COPY" for dependency, *_ in report.silent)


def test_a_bound_result_from_an_unknown_call_is_unchecked(tmp_path):
    # the body returns an unknown call's rax: the interpreter keeps only the
    # model's kept registers across that call, not its output -- every result
    # rests on the havocked value, none is checked against another
    caller, _ = _bound_program()
    body = FunctionBuilder(entry=INTERNAL).sub_rsp(0x28).call_indirect(RDX).add_rsp(0x28).ret()
    units = program_units(caller, body)
    results = analyze_units(units, model_bindings=(_binding(tmp_path, units),), external_models=_models(tmp_path),
                            assume_same_result_functions=True, assume_accessor_result_separate=True,
                            assume_accessor_private_state=True)
    analyzed = results["1:1000"]
    assert len(analyzed.normalized.same_result_uses) == 3
    report = check_program(analyzed.normalized, analyzed.unit.observation, {(1, INTERNAL): units[1].observation},
                           seeds=range(4),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.runs and report.same_result_checked == 0 and report.same_result_unchecked >= 3 * report.runs


def test_two_bindings_of_one_function_are_an_error_in_any_order(tmp_path):
    caller, body = _bound_program()
    units = program_units(caller, body)
    first = _binding(tmp_path / "a" if (tmp_path / "a").mkdir() is None else tmp_path, units)
    second_dir = tmp_path / "b"
    second_dir.mkdir()
    second = _binding(second_dir, units, entry=_get(omits_private_writes=True))
    for order in ((first, second), (second, first)):
        for private in (True, False):
            with pytest.raises(ModelError):
                analyze_units(units, model_bindings=order, external_models=_models(tmp_path),
                              assume_same_result_functions=True, assume_accessor_private_state=private)


def test_a_binding_under_another_abi_is_an_error(tmp_path):
    caller, body = _bound_program()
    units = program_units(caller, body)
    binding = _binding(tmp_path, units)
    other = load_external_models([], "x86:LE:64:default", "win64")   # a run with no models: no ABI to check
    for models in (other, None):
        with pytest.raises(ModelError):
            analyze_units(units, model_bindings=(binding,), external_models=models,
                          assume_same_result_functions=True, assume_accessor_private_state=True)


def test_a_binding_takes_no_derived_summary(tmp_path):
    (tmp_path / "summary.json").write_text(json.dumps({
        "format_version": 1, "kind": "summary", "id": "s", "version": 1, "language_id": HEADER["language_id"],
        "abi_tag": "win64", "libraries": ["CORE"], "entries": [], "source": {}}), encoding="utf-8")
    raw = {"format_version": 1, "kind": "binding", "id": "b", "executable_sha256": "a" * 64,
           "language_id": HEADER["language_id"], "abi_tag": "win64", "models": ["summary.json"], "bindings": []}
    (tmp_path / "binding.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ModelError):
        load_binding_file(tmp_path / "binding.json")


def test_the_oracle_still_sees_a_caller_visible_write_of_a_havocked_value(tmp_path):
    # the bound body stores an opaque call's value into a global the caller
    # then reads: arbitrary, but not private -- a miss the oracle must report
    caller = (FunctionBuilder().sub_rsp(0x28).call(INTERNAL)
              .ins(load(reg(R9), const(DATA_BASE))).add_rsp(0x28).ret())
    body = (FunctionBuilder(entry=INTERNAL).sub_rsp(0x28).call_indirect(RDX)
            .ins(store(const(DATA_BASE), reg(RAX))).ins(load(reg(RAX), reg(RCX))).add_rsp(0x28).ret())
    units = program_units(caller, body)
    entry = _get(omits_private_writes=True, same_result={"result": [RAX, 8], "inputs": [], "reads": [SLOT]})
    results = analyze_units(units, model_bindings=(_binding(tmp_path, units, entry=entry),),
                            external_models=_models(tmp_path), assume_same_result_functions=True,
                            assume_accessor_private_state=True)
    analyzed = results["1:1000"]
    assert analyzed.proven   # the model applies (it wrongly leaves the global out)
    report = check_program(analyzed.normalized, analyzed.unit.observation, {(1, INTERNAL): units[1].observation},
                           seeds=range(4),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert any(dependency.reader == "1:1008:0:LOAD" and reason == "write outside its run"
               for dependency, reason, *_ in report.silent)


def test_a_binding_of_another_binary_is_not_applied(tmp_path):
    results, _ = _analyze_bound(tmp_path, sha="0" * 64)
    assert f"1:{INTERNAL:x}" in results and results["1:1000"].normalized.same_result_uses == ()


def test_a_binding_to_no_function_is_an_error(tmp_path):
    with pytest.raises(ModelError):
        _analyze_bound(tmp_path, rva=0x7777)


@pytest.mark.parametrize("change, problem", [
    ({"executable_sha256": "ABC"}, "not a sha256"),
    ({"bindings": [{"rva": "0x400", "model": "bound-test/Nothing"}]}, "unknown model"),
    ({"bindings": [{"rva": "0x400", "model": "bound-test/GetObj"}, {"rva": "0x400", "model": "bound-test/GetObj"}]},
     "the same rva twice"),
    ({"language_id": "ARM:LE:32:v8"}, "another language"),
    ({"kind": "declared"}, "not a binding"),
])
def test_a_binding_file_is_validated(tmp_path, change, problem):
    (tmp_path / "bound.json").write_text(json.dumps({**HEADER, "id": "bound-test", "entries": [_get()]}),
                                         encoding="utf-8")
    raw = {"format_version": 1, "kind": "binding", "id": "b", "executable_sha256": "a" * 64,
           "language_id": HEADER["language_id"], "abi_tag": "win64", "models": ["bound.json"],
           "bindings": [{"rva": "0x400", "model": "bound-test/GetObj"}], **change}
    (tmp_path / "binding.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ModelError):
        load_binding_file(tmp_path / "binding.json")


def test_an_import_model_omitting_private_writes_needs_the_switch(tmp_path):
    entries = [_get(omits_private_writes=True), *ENTRIES[1:]]
    builder = _caller()
    for private, applied in ((False, False), (True, True)):
        image = ImageInfo("synthetic", (), (ImportedSymbol("CORE", "GetObj", None, (), ((1, GET),)),), (), ())
        results = analyze_units(program_units(builder), image_info=image, external_models=_models(tmp_path, entries),
                                assume_same_result_functions=True, assume_accessor_private_state=private)
        analyzed = results["1:1000"]
        assert bool(analyzed.proven) == applied
        assert ("accessor-private-state" in analyzed.inherited_assumptions) == applied


def test_the_oracle_runs_the_bound_body(tmp_path):
    results, caller = _analyze_bound(tmp_path)
    analyzed = results["1:1000"]
    (_, body) = program_units(*_bound_program())
    report = check_program(analyzed.normalized, analyzed.unit.observation, {(1, INTERNAL): body.observation},
                           seeds=range(8),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.same_result_checked and report.same_result_violations == [] and report.silent == []
    assert report.same_result_unchecked


# -- proven state-keeping calls (docs 25.26) --------------------------------------

PURE = CODE_BASE + 0x600


def _between_pure(*callee_rows, builder_class=FunctionBuilder, finish=None):
    """R007's shape with ``call PURE`` between Get1 and Get2 (source_B's place);
    PURE is a program function made of ``callee_rows`` then ``ret``."""
    caller = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(GET).ins(copy(reg(RBP), reg(RAX)))
    caller.ins(add(T, reg(RBP), const(0x30)), store(T, reg(RDI, 4)))
    caller.call(PURE)
    caller.ins(copy(reg(RCX), reg(RBX))).call(GET)
    caller.ins(add(T, reg(RAX), const(0x34)), store(T, reg(R12, 4)))
    caller.ins(copy(reg(RCX), reg(RBX))).call(GET)
    caller.ins(add(T, reg(RAX), const(0x30)), load(reg(R9, 4), T))
    caller.add_rsp(0x28).ret()
    callee = builder_class(entry=PURE)
    for row in callee_rows:
        row(callee) if callable(row) else callee.ins(*row)
    (finish or (lambda builder: builder.ret()))(callee)
    return caller, callee


PURE2 = CODE_BASE + 0x700


def _analyze_pure(tmp_path, caller, callee):
    image = ImageInfo("synthetic", (), (ImportedSymbol("CORE", "GetObj", None, (), ((1, GET),)),), (), ())
    other = FunctionBuilder(entry=PURE2).ins(load(reg(RAX, 4), const(DATA_BASE, 8))).ret()   # pure too
    results = analyze_units(program_units(caller, callee, other), image_info=image,
                            external_models=_models(tmp_path, SEPARATE), assume_same_result_functions=True,
                            assume_accessor_result_separate=True)
    return results["1:1000"]


def _return_row(builder, *ops):
    """A terminal (return) instruction of exactly ``ops``."""
    from synthetic import _Instruction

    builder._rows.append(_Instruction(list(ops), "return"))
    return builder


READS_A_GLOBAL = [(load(reg(RAX, 4), const(DATA_BASE, 8)),), (add(reg(RAX, 4), reg(RAX, 4), const(2, 4)),)]


def test_a_pure_callee_keeps_the_accessor_state(tmp_path):
    caller, callee = _between_pure(*READS_A_GLOBAL)
    analyzed = _analyze_pure(tmp_path, caller, callee)
    uses = analyzed.normalized.same_result_uses
    assert len(uses) == 3 and len({atom for *_, atom in uses}) == 1
    assert any(claim.startswith("proof:") for _, _, claims, _ in uses for claim in claims)
    read = _read(analyzed, caller)
    assert read.reaches(RDI, 4) and not read.reaches(R12, 4) and _complete_but_for_pushes(analyzed, read)
    assert "accessor-hidden-state-in-memory" in analyzed.inherited_assumptions
    assert not any(label.startswith("accessor-state-preserved-by:proof") for label in analyzed.inherited_assumptions)


def _refused(tmp_path, caller, callee):
    """Whether Get2 (after the call of PURE) sees another accessor state than Get1."""
    analyzed = _analyze_pure(tmp_path, caller, callee)
    states = [value[9] for _, value in sorted(analyzed.normalized.pointer_rows) if value[0] == "same_result"]
    return analyzed, len(states) < 2 or states[1] != states[0]


@pytest.mark.parametrize("rows, finish", [
    ([(store(const(DATA_BASE, 8), reg(RDX)),)], None),                                  # the leaf table setter
    ([lambda builder: builder.push(RBX), lambda builder: builder.pop(RBX)], None),        # a stack store (v1)
    ([lambda builder: builder.call(PURE2)], None),                                       # a call, even of a pure one
    ([(op("CALLOTHER", [const(0x11, 4)]),)], None),                                       # a user op
    ([(copy(reg(0x40, 2), reg(RDX, 2)),)], None),                                         # a segment register
    ([(op("INT_SUB", [reg(RSP), const(8)], reg(RSP)),)],                                  # lea rsp,[rsp-8]; ret 8
     lambda builder: _return_row(builder, load(reg(RIP), reg(RSP)), add(reg(RSP), reg(RSP), const(16)),
                                 op("RETURN", [reg(RIP)]))),
    ([], lambda builder: builder.ret(realistic=False)),                                   # RETURN of a register
    ([], lambda builder: _return_row(builder, load(reg(RIP), reg(RSP)), add(reg(RSP), reg(RSP), const(8)),
                                     op("RETURN", [reg(RAX)]))),                           # pops, returns elsewhere
], ids=["table-setter", "push-pop", "call", "callother", "segment", "ret-8", "bare-return", "returns-elsewhere"])
def test_a_callee_without_the_proof_changes_the_state(tmp_path, rows, finish):
    caller, callee = _between_pure(*READS_A_GLOBAL, *rows, finish=finish)
    _, refused = _refused(tmp_path, caller, callee)
    assert refused


def test_a_call_pushing_through_another_register_gets_no_proof(tmp_path):
    # the caller's "call" pushes its continuation through rax; the callee
    # adds 8 to rax (so the shape's stack delta checks out) and returns
    # through rsp: [rsp] is not that continuation
    caller, callee = _between_pure((op("INT_ADD", [reg(RAX), const(8)], reg(RAX)),))
    row = next(item for item in caller._rows if item.kind == "call" and item.call_target == PURE)
    row.ops = [sub(reg(RAX), reg(RAX), const(8)), store(reg(RAX), const(caller._address(caller._rows.index(row) + 1))),
               op("CALL", [ram(PURE)])]
    _, refused = _refused(tmp_path, caller, callee)
    assert refused


def test_a_call_overwriting_its_pushed_continuation_gets_no_proof(tmp_path):
    # push the continuation, overwrite it, call: the callee's ordinary ret
    # goes to the overwritten address
    caller, callee = _between_pure(*READS_A_GLOBAL)
    row = next(item for item in caller._rows if item.kind == "call" and item.call_target == PURE)
    row.ops = [sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(caller._address(caller._rows.index(row) + 1))),
               store(reg(RSP), const(PURE + 0x100)), op("CALL", [ram(PURE)])]
    _, refused = _refused(tmp_path, caller, callee)
    assert refused


class _MisroutedBranch(FunctionBuilder):
    """Row 0's CBRANCH goes to ``bad`` in p-code, its observed flow to ``prep``."""

    def to_json(self) -> dict:
        raw = super().to_json()
        raw["instructions"][0]["flow_targets"] = [self._coordinate(self._address(self._labels["prep"]))]
        return raw


def test_a_branch_whose_metadata_disagrees_refuses(tmp_path):
    # observed: CBRANCH -> prep (rsp -= 8), bad (rsp += 8), jmp done: the stack
    # balances; real p-code skips prep: RET reads [S+8]
    def body(builder):
        builder.cbranch("bad", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
        builder.label("done").ret()
        builder.label("prep").ins(op("INT_SUB", [reg(RSP), const(8)], reg(RSP)))
        builder.label("bad").ins(op("INT_ADD", [reg(RSP), const(8)], reg(RSP)))
        builder.branch("done")
    caller, callee = _between_pure(body, builder_class=_MisroutedBranch, finish=lambda builder: None)
    _, refused = _refused(tmp_path, caller, callee)
    assert refused


def test_the_oracle_runs_a_pure_callee(tmp_path):
    caller, callee = _between_pure(*READS_A_GLOBAL)
    analyzed = _analyze_pure(tmp_path, caller, callee)
    units = program_units(_resolver(), callee)
    report = check_program(analyzed.normalized, analyzed.unit.observation,
                           {(1, GET): units[0].observation, (1, PURE): units[1].observation}, seeds=range(6),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.same_result_checked and report.same_result_violations == [] and report.silent == []
