"""Design I-ID (docs 25.99): the SSA import identity rests on import-slots-hold-their-exports alone,
not on globals-disjoint-from-stack, whose non-stack claim it never makes. Every case states the
globals-disjoint setting it runs under (``gd``)."""

from dataclasses import replace

import pytest

from synthetic import DATA_BASE, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, copy, load, ram, reg, store, tmp
from test_import_ssa_targets import INFO, KEEP, SLOT, _analyze, _caller
from tdo_v2.interprocedural import import_call_sites
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.summary_engine import run_assumptions

GD = "globals-disjoint-from-stack"
SLOTS = "import-slots-hold-their-exports"
FRAME = "entry-values-do-not-address-the-new-frame"


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _switching(monkeypatch):
    # (a stack switch in the program: globals-disjoint asked ON is withdrawn for the run)
    import tdo_v2.interprocedural as ip

    monkeypatch.setattr(ip, "program_switches_stack", lambda *args, **kwargs: {"1:1000": ("switch",)})


def _labels(item, results):
    return (dict(item.declared), sorted(item.proven), tuple(sorted(map(repr, item.normalized.premise_uses))),
            tuple(sorted(run_assumptions(results))),
            tuple((key, repr(other.summary)) for key, other in sorted(results.items())))


def _no_globals_label(item, results):
    assert GD not in run_assumptions(results)
    assert not any(GD in use for use in item.normalized.premise_uses)


@pytest.mark.parametrize("switch", (False, True), ids=("gd-off", "gd-withdrawn"))
def test_ssa_identity_rests_on_import_slots_alone(monkeypatch, switch):
    if switch:
        _switching(monkeypatch)
    caller = _caller(copy(reg(RCX), const(DATA_BASE + 0x200)))
    item, results = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret(), globals_disjoint=switch)
    call = next(key for key in item.declared if key.endswith(":CALLIND"))
    assert item.declared[call] == "external-model:crt-win64/strlen@v8" and call in item.proven
    assert SLOTS in run_assumptions(results)
    assert (SLOTS, "resolution", call) in item.normalized.premise_uses
    assert (SLOTS, "admission", call) in item.normalized.premise_uses
    _no_globals_label(item, results)
    # (no normalization use: the identity was a candidate query)
    assert not item.normalized.assumes_import_slots_hold_exports


def test_withdrawn_globals_disjoint_equals_a_run_without_it(monkeypatch):
    callee = FunctionBuilder(entry=KEEP).ret()
    caller = _caller(copy(reg(RCX), const(DATA_BASE + 0x200)))
    off = _labels(*_analyze(monkeypatch, caller, callee, globals_disjoint=False))
    slots_off = _labels(*_analyze(monkeypatch, caller, callee, imports=False, globals_disjoint=False))
    assert off[0] and not slots_off[0] and SLOTS not in slots_off[3]
    _analyze(monkeypatch, caller, callee, globals_disjoint=True)             # (warm: on, then off again)
    assert _labels(*_analyze(monkeypatch, caller, callee, globals_disjoint=False)) == off
    assert _labels(*_analyze(monkeypatch, caller, callee, imports=False, globals_disjoint=False)) == slots_off
    assert _labels(*_analyze(monkeypatch, caller, callee, imports=False, globals_disjoint=True))[0] == {}
    with monkeypatch.context() as patched:
        _switching(patched)
        assert _labels(*_analyze(monkeypatch, caller, callee, globals_disjoint=True)) == off


@pytest.mark.parametrize("gd", ("on", "off", "withdrawn"))
def test_a_model_resting_on_globals_disjoint_is_refused_without_it(monkeypatch, gd):
    from tdo_v2.summary_store import ExternalModels

    original = ExternalModels.lookup

    def lookup(self, symbol):
        found = original(self, symbol)
        if found is None or not found[1].label.endswith("strlen@v8"):
            return found
        return found[0], replace(found[1], inherited=(*found[1].inherited, GD))

    monkeypatch.setattr(ExternalModels, "lookup", lookup)
    if gd == "withdrawn":
        _switching(monkeypatch)
    item, _ = _analyze(monkeypatch, _caller(), FunctionBuilder(entry=KEEP).ret(), globals_disjoint=gd != "off")
    assert bool(item.declared) is (gd == "on")
    if gd != "on":
        assert any(GD in reason for reason in item.refused_models.values())


@pytest.mark.parametrize("frame", (True, False))
def test_spill_and_global_store_rest_on_the_new_frame_premise(monkeypatch, frame):
    # globals-disjoint OFF: a private-frame reload drops the constant-address writer only under
    # entry-values-do-not-address-the-new-frame -- recorded, never silent (Fable r1 finding 1)
    spill, reload_at = tmp(0x700), tmp(0x708)
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), ram(SLOT)))
              .ins(add(spill, reg(RSP), const(0x20)), store(spill, reg(RBX)))
              .ins(store(const(DATA_BASE + 0x200), reg(RDX)))
              .ins(add(reload_at, reg(RSP), const(0x20)), load(reg(RBX), reload_at))
              .call_indirect(RBX).add_rsp(0x28).ret())
    item, results = _analyze(monkeypatch, caller, globals_disjoint=False, assume_entry_values_not_frame=frame)
    assert import_call_sites(item.unit, INFO) == {}
    assert bool(item.declared) is frame
    if frame:
        assert FRAME in run_assumptions(results)
        assert any(FRAME in use for use in item.normalized.premise_uses)
        _no_globals_label(item, results)


def _escaped_frame_store():
    # the frame slot's address is passed to a callee, then the slot is written before the import
    # slot is read: an escaped (non-private) stack store
    at, again = tmp(0x700), tmp(0x708)
    return (FunctionBuilder().sub_rsp(0x28).ins(add(at, reg(RSP), const(0x20)), copy(reg(RCX), at))
            .call(KEEP).ins(add(again, reg(RSP), const(0x20)), store(again, reg(RDX)))
            .ins(copy(reg(RBX), ram(SLOT))).call(KEEP).call_indirect(RBX).add_rsp(0x28).ret())


def _caller_frame_store():
    at = tmp(0x700)
    return (FunctionBuilder().sub_rsp(0x28).ins(add(at, reg(RSP), const(0x30)), store(at, reg(RCX)))
            .ins(copy(reg(RBX), ram(SLOT))).call(KEEP).call_indirect(RBX).add_rsp(0x28).ret())


def _unknown_store():
    return (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RDX), reg(RCX)))
            .ins(copy(reg(RBX), ram(SLOT))).call(KEEP).call_indirect(RBX).add_rsp(0x28).ret())


@pytest.mark.parametrize("on", (True, False), ids=("gd-on", "gd-off"))
@pytest.mark.parametrize("shape", (_escaped_frame_store, _caller_frame_store, _unknown_store),
                         ids=("escaped-frame", "caller-frame", "unknown"))
def test_a_store_that_may_reach_the_slot_before_its_read_refuses(monkeypatch, shape, on):
    # a stack store the analysis can keep off the slot only with globals-disjoint (escaped frame
    # slot, the caller's frame), or no store it can keep off at all (an unknown pointer)
    item, _ = _analyze(monkeypatch, shape(), FunctionBuilder(entry=KEEP).ret(), globals_disjoint=on)
    if shape is _unknown_store or not on:
        assert not item.declared
    else:
        assert list(item.declared.values()) == ["external-model:crt-win64/strlen@v8"]


@pytest.mark.parametrize("on", (True, False), ids=("gd-on", "gd-off"))
def test_normalization_takes_no_import_atom_without_globals_disjoint(monkeypatch, on):
    # (r2.7 item 10) no call: what the switch changes is normalization's import atoms only --
    # without globals-disjoint none, so import-slots ON and OFF normalize alike
    def facts(imports):
        caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), ram(SLOT)))
                  .ins(store(const(DATA_BASE + 0x300), reg(RBX))).ins(load(reg(RCX), reg(RBX)))
                  .add_rsp(0x28).ret())
        normalized = _analyze(monkeypatch, caller, imports=imports, globals_disjoint=on)[0].normalized
        inputs = normalized.forward_inputs
        return (repr(normalized.memory_ssa), normalized.nonstack_spans, tuple(sorted(map(repr, normalized.premise_uses))),
                normalized.assumes_import_slots_hold_exports,
                None if inputs is None else (inputs.nonstack_objects, inputs.nonstack_spans))

    with_slots, without = facts(True), facts(False)
    assert with_slots[3] is on
    assert (with_slots == without) is not on


@pytest.mark.parametrize("active", (False, True))
def test_identity_query_registers_no_import_atom_without_active(monkeypatch, active):
    from tdo_v2 import relative_memory as memory

    item, _ = _analyze(monkeypatch, _caller(), FunctionBuilder(entry=KEEP).ret(), globals_disjoint=True)
    instruction = item.unit.observation.instructions[4]
    request = (f"1:{instruction.address.byte_offset:x}:0:COPY", instruction.operations[0].inputs[0])
    slots = memory.ImportSlots(INFO)
    slots.active = active
    assert (slots.atom(1, SLOT) is None) is not active               # normalization's gate: unchanged
    assert slots.atom(1, SLOT, identity=True) is not None             # the identity alone
    built = []
    original = memory._final_projector

    def capture(*args):
        built.append(original(*args))
        return built[-1]

    monkeypatch.setattr(memory, "_final_projector", capture)
    token = memory.IMPORT_SLOTS.set(slots)
    try:
        assert memory.import_values(item.normalized, item.unit.observation, [request], INFO)[request].name == "strlen"
    finally:
        memory.IMPORT_SLOTS.reset(token)
    projector, = built
    assert projector._import_identity
    # (the non-stack claim's registry: only with globals-disjoint-from-stack)
    assert bool(projector._import_atoms) is active


@pytest.mark.parametrize("prior", (False, True), ids=("scope-unused", "scope-used"))
@pytest.mark.parametrize("fails", (False, True), ids=("succeeds", "fails"))
def test_identity_query_keeps_tracking_and_normalization_state(monkeypatch, fails, prior):
    # (Astra r2 P2-2) success and failure: ``used`` membership, ``IMAGE_BASE_TRACKING.found`` and the
    # normalized function are what they were; ``tracking.proofs`` is a diagnostic (docs 25.99)
    from tdo_v2 import relative_memory as memory

    item, _ = _analyze(monkeypatch, _caller(), FunctionBuilder(entry=KEEP).ret(), globals_disjoint=False)
    row = item.unit.observation.instructions[4]
    request = (f"1:{row.address.byte_offset:x}:0:COPY", row.operations[0].inputs[0])
    scope = item.normalized.memory_ssa.function_scope
    slots = memory.ImportSlots(INFO)
    slots.used |= {"other", *((scope,) if prior else ())}
    used = set(slots.used)
    tracking = memory.ImageBaseTracking(((0x1000, 0x2fff),))
    tracking.found.add("earlier")
    normalized = item.normalized

    def state():
        inputs = normalized.forward_inputs
        return (repr(normalized.memory_ssa), normalized.nonstack_spans, normalized.premise_uses,
                normalized.assumes_import_slots_hold_exports, inputs.nonstack_objects, inputs.nonstack_spans)

    before = state()
    if fails:
        original = memory._Projector._expression_for_input

        def broken(self, *args):
            original(self, *args)
            raise RuntimeError("candidate query failed")

        monkeypatch.setattr(memory._Projector, "_expression_for_input", broken)
    tokens = [(memory.IMPORT_SLOTS, memory.IMPORT_SLOTS.set(slots)),
              (memory.IMAGE_BASE_TRACKING, memory.IMAGE_BASE_TRACKING.set(tracking))]
    try:
        if fails:
            with pytest.raises(RuntimeError, match="candidate query failed"):
                memory.import_values(normalized, item.unit.observation, [request], INFO)
        else:
            assert memory.import_values(normalized, item.unit.observation, [request], INFO)[request].name == "strlen"
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)
    assert slots.used == used and slots.active is False
    assert tracking.found == {"earlier"}
    assert state() == before


def test_captured_policy_without_globals_disjoint_refuses_a_changed_policy(monkeypatch):
    # (Astra r2 P2-1) a gd-OFF run's retained proofs (realloc copy proofs, import-slots ON) verify,
    # are refused once the captured policy changes, and verify again when it is restored
    from synthetic import program_units
    from test_external_models import _image
    from test_realloc_contents import case, contracts
    from tdo_v2._call_activation import _policy
    from tdo_v2._forward_memory import RefinementRefused, verification_session
    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.summary_store import load_external_models
    from test_allocation_lifetime import MODELS as LIFETIME_MODELS

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    models = load_external_models(LIFETIME_MODELS, "x86:LE:64:default", "win64")
    builder, _ = case()
    results = analyze_units(program_units(builder), image_info=_image(), external_models=models,
                            lifecycle_contracts=contracts(models), private_frame_above=40,
                            assume_globals_disjoint_from_stack=False, assume_entry_values_not_frame=False,
                            assume_opaque_callees_leave_no_stack_addresses=False,
                            assume_import_slots_hold_exports=True)
    item = results["1:1000"]
    plan = item.normalized.forward_inputs.read_separations
    assert plan is not None and plan.copy_proofs
    slots = plan.source.normalization_context[2]
    assert slots is not None and slots.active is False and plan.source.normalization_context[3] is False
    with verification_session():
        plan.verify()
        with _policy(item):
            pass
        slots.active = True
        try:
            with pytest.raises(RefinementRefused, match="policies changed"):
                plan.verify()
            with pytest.raises(RefinementRefused, match="policies changed"):
                with _policy(item):
                    pass
        finally:
            slots.active = False
        plan.verify()


@pytest.mark.parametrize("scope", ("function", "run"))
def test_an_exhausted_identity_query_without_globals_disjoint(monkeypatch, scope):
    # (Astra r2 P2-2) the query is a consumer step of the round (as with globals-disjoint on): a
    # function budget fails that function alone (sticky -- its callers see an opaque call); a run
    # budget finalizes the run with the round-1 publication (no SSA admission)
    import tdo_v2.relative_memory as memory
    from tdo_v2.resource_limits import AnalysisBudgetExceeded

    original, asked = memory.import_values, []

    def exhausted(*args, **kwargs):
        asked.append(original(*args, **kwargs))      # (the real query ran, then its budget ran out)
        raise AnalysisBudgetExceeded("work", "injected", scope=scope)

    monkeypatch.setattr(memory, "import_values", exhausted)
    item, results = _analyze(monkeypatch, _caller(), FunctionBuilder(entry=KEEP).ret(), globals_disjoint=False)
    assert asked and any(asked)          # (reached, and it had found the identity)
    assert not item.declared and SLOTS not in run_assumptions(results)
    assert type(results[f"1:{KEEP:x}"].normalized) is NormalizedFunction     # (the other function: untouched)
    if scope == "function":
        assert type(item.normalized) is not NormalizedFunction and item.failure_detail
    else:
        assert type(item.normalized) is NormalizedFunction
