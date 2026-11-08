"""Address replay authority is rechecked on every session-local cache hit."""

from dataclasses import replace

import pytest

from synthetic import program_units
from test_finite_read_addresses import _body
from test_fault_premise import _pe
from tdo_v2 import _forward_memory as memory
from tdo_v2.interprocedural import analyze_units


@pytest.fixture(autouse=True)
def forward_on(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def _plan(*, fault=False):
    units = program_units(_body(fault=fault))
    options = dict(assume_faults_end_execution=True, assume_stock_ghidra_translator=True,
                   exception_directory=_pe()) if fault else {}
    item = analyze_units(units, **options)["1:1000"]
    plan = item.normalized.forward_inputs.read_separations
    assert plan is not None and plan.address_reads
    assert memory._address_verification_pin(plan) is not None
    return plan


def _count(monkeypatch):
    calls = []
    original = memory.prepare_memory_refinement

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(memory, "prepare_memory_refinement", counted)
    return calls


def test_only_a_completed_derivation_is_reused_inside_one_session(monkeypatch):
    plan = _plan()
    calls = _count(monkeypatch)
    with memory.verification_session():
        plan.verify()
        with memory.verification_session():
            plan.verify()
        assert len(calls) == 1
    assert memory._VERIFIED.get() is None
    plan.verify()
    assert len(calls) == 2  # A later owner operation must fully derive again.


@pytest.mark.parametrize("field", ("unit", "normalized", "inherited_assumptions", "declared"))
def test_changed_source_identity_or_dependencies_cannot_use_a_warm_hit(monkeypatch, field):
    plan = _plan()
    calls = _count(monkeypatch)
    source = plan.source
    with memory.verification_session():
        plan.verify()
        old = getattr(source, field)
        value = {"unit": program_units(_body())[0], "normalized": replace(source.normalized),
                 "inherited_assumptions": frozenset({"new-input-dependency"}),
                 "declared": {"new-call": "new-input-dependency"}}[field]
        object.__setattr__(source, field, value)
        try:
            with pytest.raises(memory.RefinementRefused):
                plan.verify()
        finally:
            object.__setattr__(source, field, old)
        plan.verify()
    assert len(calls) <= 2


def test_nested_forward_input_map_mutation_is_snapshotted_not_retained(monkeypatch):
    plan = _plan()
    calls = _count(monkeypatch)
    observed = plan.baseline.forward_inputs.observed_calls
    with memory.verification_session():
        plan.verify()
        observed["unused-call"] = {"nested": [1]}
        plan.verify()
        assert len(calls) == 2
        observed["unused-call"]["nested"].append(2)
        plan.verify()
        assert len(calls) == 3
        plan.verify()
        assert len(calls) == 3
        del observed["unused-call"]


@pytest.mark.parametrize("field", ("requires", "signature", "proofs", "address_reads", "assumptions"))
def test_forced_same_object_claim_mutation_does_not_reuse_its_receipt(monkeypatch, field):
    plan = _plan()
    calls = _count(monkeypatch)
    with memory.verification_session():
        plan.verify()
        old = getattr(plan, field)
        changed = {"requires": ("forged",), "signature": ("forged",),
                   "proofs": (plan.address_reads[0],),
                   "address_reads": (replace(plan.address_reads[0], spans=plan.address_reads[0].spans[:-1]),),
                   "assumptions": ("forged",)}[field]
        object.__setattr__(plan, field, changed)
        try:
            with pytest.raises(memory.RefinementRefused):
                plan.verify()
        finally:
            object.__setattr__(plan, field, old)
        plan.verify()
    assert len(calls) == 2


@pytest.mark.parametrize("policy", ("forward", "indexed", "alias", "activation"))
def test_changed_current_environment_and_activation_are_checked_on_hits(monkeypatch, policy):
    from tdo_v2._activation_entry import ACTIVE_ENTRY, ActivationEntry
    from tdo_v2.may_alias import ENTRY_VALUES_NOT_FRAME

    plan = _plan()
    token = None
    with memory.verification_session():
        plan.verify()
        if policy == "forward":
            monkeypatch.setenv("TDO_V2_FORWARD", "0")
        elif policy == "indexed":
            monkeypatch.setenv("TDO_V2_INDEX_ADDRESSES", "0")
        elif policy == "alias":
            token = ENTRY_VALUES_NOT_FRAME.set(not ENTRY_VALUES_NOT_FRAME.get())
        else:
            token = ACTIVE_ENTRY.set(ActivationEntry(plan.unit.scopes.function.scope,
                ("other-caller", "other-call"), (), (), ()))
        try:
            with pytest.raises(memory.RefinementRefused):
                plan.verify()
        finally:
            if token is not None:
                (ENTRY_VALUES_NOT_FRAME if policy == "alias" else ACTIVE_ENTRY).reset(token)


def test_import_slot_contents_and_activation_policy_are_current_on_every_hit(monkeypatch):
    from tdo_v2.relative_memory import IMPORT_SLOTS, ImportSlots

    plan = _plan()
    imports = ImportSlots(None)
    context = list(plan.source.normalization_context)
    context[2], context[3] = imports, False
    source = replace(plan.source, normalization_context=tuple(context))
    token = IMPORT_SLOTS.set(imports)
    try:
        plan = memory.prepare_memory_refinement(source, dict(plan.options), assumptions=plan.assumptions)
        assert plan is not None
        calls = _count(monkeypatch)
        with memory.verification_session():
            plan.verify()
            imports.slots[(1, 0x5000)] = ("test", "first")
            plan.verify()
            assert len(calls) == 2
            imports.active = True
            with pytest.raises(memory.RefinementRefused):
                plan.verify()
    finally:
        IMPORT_SLOTS.reset(token)


def test_changed_captured_context_is_revalidated_before_a_hit():
    plan = _plan()
    original = plan.source.normalization_context
    changed = (not original[0], *original[1:])
    with memory.verification_session():
        plan.verify()
        object.__setattr__(plan.source, "normalization_context", changed)
        try:
            with pytest.raises(memory.RefinementRefused):
                plan.verify()
        finally:
            object.__setattr__(plan.source, "normalization_context", original)
        plan.verify()


def test_peer_metadata_mutations_require_full_rederivation_not_an_old_hit(monkeypatch):
    plan = _plan()
    peer = replace(plan.source)
    calls = _count(monkeypatch)
    with memory.verification_session():
        plan.verify()
        object.__setattr__(plan, "peers", (("peer", peer),))
        plan.verify()
        assert len(calls) == 2
        object.__setattr__(peer, "inherited_assumptions", frozenset({"new-peer-dependency"}))
        plan.verify()
        assert len(calls) == 3
        plan.verify()
        assert len(calls) == 3
    # Address derivation has no semantic peer claims; their addition does not
    # grant an effect. The changed metadata is nevertheless never a cache hit.


def test_current_fault_revocation_invalidates_a_warm_address_receipt():
    plan = _plan(fault=True)
    receipt = dict(plan.source.normalization_options)["_once_control"]
    state = receipt._proof[4]
    original = state["discharged"]
    with memory.verification_session():
        plan.verify()
        state["discharged"] = frozenset()
        try:
            with pytest.raises(memory.RefinementRefused):
                plan.verify()
        finally:
            state["discharged"] = original
        plan.verify()


def test_forced_fault_receipt_authority_mutation_is_rejected_on_a_warm_hit():
    plan = _plan(fault=True)
    receipt = dict(plan.source.normalization_options)["_once_control"]
    original = receipt._proof
    with memory.verification_session():
        plan.verify()
        object.__setattr__(receipt, "_proof", ())
        try:
            with pytest.raises(memory.RefinementRefused):
                plan.verify()
        finally:
            object.__setattr__(receipt, "_proof", original)
        plan.verify()


@pytest.mark.parametrize("mode", ("unissued", "self", "mutual"))
def test_prior_plan_authority_and_cycles_are_not_skipped_on_hits(mode):
    plan = _plan()
    inputs = plan.baseline.forward_inputs
    with memory.verification_session():
        plan.verify()
        if mode == "unissued":
            prior = object()
        elif mode == "self":
            prior = plan
        else:
            other_inputs = replace(inputs)
            other_baseline = replace(plan.baseline, forward_inputs=other_inputs)
            prior = replace(plan, baseline=other_baseline,
                            source=replace(plan.source, normalized=other_baseline))
            object.__setattr__(other_inputs, "read_separations", plan)
        object.__setattr__(inputs, "read_separations", prior)
        try:
            with pytest.raises(memory.RefinementRefused):
                plan.verify()
        finally:
            object.__setattr__(inputs, "read_separations", None)
        plan.verify()


def test_mutable_provider_options_are_not_cached(monkeypatch):
    plan = _plan()
    options = {**dict(plan.options), "opaque_value_provider": object()}
    plan = memory.prepare_memory_refinement(plan.source, options, assumptions=plan.assumptions)
    assert plan is not None and memory._address_verification_pin(plan) is None
    calls = _count(monkeypatch)
    with memory.verification_session():
        plan.verify()
        plan.verify()
    assert len(calls) == 2


def test_readonly_image_contents_without_a_generation_receipt_are_not_cached(monkeypatch):
    class NoBytes:
        def value(self, *args):
            return None

    plan = _plan()
    options = {**dict(plan.options), "readonly_image": NoBytes()}
    plan = memory.prepare_memory_refinement(plan.source, options, assumptions=plan.assumptions)
    assert plan is not None and memory._address_verification_pin(plan) is None
    calls = _count(monkeypatch)
    with memory.verification_session():
        plan.verify()
        plan.verify()
    assert len(calls) == 2


def test_captured_image_tracking_callback_is_not_assumed_immutable():
    from tdo_v2.relative_memory import ImageBaseTracking

    plan = _plan()
    context = list(plan.source.normalization_context)
    context[4] = ImageBaseTracking(())
    source = replace(plan.source, normalization_context=tuple(context))
    assert memory._address_verification_pin(replace(plan, source=source)) is None


def test_failed_derivation_never_creates_a_successful_cache_entry(monkeypatch):
    plan = _plan()
    original = memory.prepare_memory_refinement
    with memory.verification_session():
        monkeypatch.setattr(memory, "prepare_memory_refinement", lambda *a, **k: None)
        with pytest.raises(memory.RefinementRefused):
            plan.verify()
        assert id(plan) not in memory._VERIFIED.get()
        monkeypatch.setattr(memory, "prepare_memory_refinement", original)
        plan.verify()
