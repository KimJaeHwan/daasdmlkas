"""2b-P P-c5 (design r5 D): recording completeness is checked against the
UNPADDED support; deleting a necessary use or consumption edge makes it fail
(the check is not vacuous)."""

from dataclasses import replace

from synthetic import CODE_BASE, RSP, FunctionBuilder, const, program_units, reg, register_evidence, store
from tools.graph_fidelity import premise_acceptance as acceptance
from tdo_v2.interprocedural import analyze_units
from tdo_v2.premises import PremiseResolver
from tdo_v2.producer_support import producer_supports
from tdo_v2.return_relations import certificate_supports

MAIN, CALLEE = CODE_BASE, CODE_BASE + 0x800
LABEL = "globals-disjoint-from-stack"


def _program():
    """The callee's summary excludes its constant-address write from its own
    stack object only under globals-disjoint (a summary-stage use); the
    caller's effect of it changes with it."""
    callee = (FunctionBuilder(entry=CALLEE).sub_rsp(0x18)
              .ins(store(reg(RSP), const(7, 8)), store(const(0x4000), const(1, 8))).add_rsp(0x18).ret())
    caller = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(CALLEE).add_rsp(0x28).ret()
    return program_units(caller, callee, registers=register_evidence(caller.arch))


def _measure(mutate=None):
    on_results = analyze_units(_program(), assume_globals_disjoint_from_stack=True)
    off_results = analyze_units(_program(), assume_globals_disjoint_from_stack=False)
    if mutate is not None:
        mutate(on_results)
    certificates = acceptance.certificates_of(on_results)
    on = acceptance.claims(on_results, certificates)
    off = acceptance.claims(off_results, acceptance.certificates_of(off_results))
    resolver = PremiseResolver()
    supports = certificate_supports(certificates, on_results, resolver)
    _, producers = producer_supports(on_results, resolver)
    return acceptance.check(LABEL, on, off, supports, producers)


def test_every_claim_the_switch_changes_lists_it_unpadded():
    found = _measure()
    assert found["changed"] > 0, found
    assert found["missing"] == 0, found


def test_deleting_the_callees_use_record_is_reported_missing():
    def mutate(results):
        callee = results[f"1:{CALLEE:x}"]
        callee.summary = replace(callee.summary, premise_uses=tuple(
            row for row in callee.summary.premise_uses if row[0] != LABEL))
        callee.normalized = replace(callee.normalized, premise_uses=tuple(
            row for row in callee.normalized.premise_uses if row[0] != LABEL))
    found = _measure(mutate)
    assert found["missing"] > 0, found
    # the padded (published) set still names it: padding alone would have hidden this
    assert found["covered_only_by_padding"] > 0, found


def test_deleting_the_consumption_edge_is_reported_missing():
    def mutate(results):
        results[f"1:{MAIN:x}"].consumed = {}
        caller = results[f"1:{MAIN:x}"]
        caller.normalized = replace(caller.normalized, premise_uses=tuple(
            row for row in caller.normalized.premise_uses if row[0] != LABEL))
        if caller.summary is not None:
            caller.summary = replace(caller.summary, premise_uses=tuple(
                row for row in caller.summary.premise_uses if row[0] != LABEL))
    found = _measure(mutate)
    assert any(key == f"1:{MAIN:x}" for key, _ in found["missing_rows"]), found


def _frame_measure(mutate=None):
    """Astra pc5 r1 P1-1: `sub rsp; [rsp]=7; [rcx]=1; rax=[rsp]; rax=0; add rsp;
    ret` -- withdrawing entry-values changes alias facts and the graph, not
    the summary or the certificate: only the graph claim sees it."""
    from synthetic import RAX, RCX, copy, load

    label = "entry-values-do-not-address-the-new-frame"
    body = (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(store(reg(RSP), const(7, 8)))
            .ins(store(reg(RCX), const(1, 8))).ins(load(reg(RAX), reg(RSP))).ins(copy(reg(RAX), const(0)))
            .add_rsp(0x28).ret())

    def units():
        return program_units(body, registers=register_evidence(body.arch))
    on_results = analyze_units(units(), assume_entry_values_not_frame=True)
    off_results = analyze_units(units(), assume_entry_values_not_frame=False)
    if mutate is not None:
        mutate(on_results, label)
    certificates = acceptance.certificates_of(on_results)
    on = acceptance.claims(on_results, certificates)
    off = acceptance.claims(off_results, acceptance.certificates_of(off_results))
    resolver = PremiseResolver()
    _, producers = producer_supports(on_results, resolver)
    return acceptance.check(label, on, off, certificate_supports(certificates, on_results, resolver), producers)


def test_a_graph_only_change_is_a_claim():
    found = _frame_measure()
    assert found["changed_by_kind"].get("graph", 0) > 0 and found["missing"] == 0, found


def test_deleting_a_graph_only_use_is_reported_missing():
    def mutate(results, label):
        for item in results.values():
            item.normalized = replace(item.normalized, premise_uses=tuple(
                row for row in item.normalized.premise_uses if row[0] != label))
    assert _frame_measure(mutate)["missing"] > 0


def test_external_models_are_selected_only_by_an_external_model_premise():
    """Astra pc5 r1 P2-1: a p-code op model premise (not withdrawn by the
    switch) does not select external-models."""
    from types import SimpleNamespace
    from tdo_v2.premises import PremiseKind, PremiseRef

    def ref(kind, name):
        return PremiseRef(kind, name, "0" * 64)

    models = SimpleNamespace(files=(SimpleNamespace(entries=(SimpleNamespace(label="external-model:crt/memcpy@v1"),),
                                                    declares=(("crt:no-sbrk", "s", "f"),)),))
    withdrawn = acceptance.withdrawn_by("external-models", models)
    assert not acceptance.selected("external-models", {ref(PremiseKind.MODEL, "pcodeop-model:x86-markers/LOCK@v1")},
                                   withdrawn)
    assert acceptance.selected("external-models", {ref(PremiseKind.MODEL, "external-model:crt/memcpy@v1")}, withdrawn)
    assert acceptance.selected("external-models", {ref(PremiseKind.ASSUMPTION, "crt:no-sbrk")}, withdrawn)
    assert acceptance.selected("external-models", {
        ref(PremiseKind.MODEL, "accessor-state-preserved-by:external-model:crt/memcpy@v1")}, withdrawn)


def test_a_template_resting_on_a_switched_off_premise_is_rejected(tmp_path):
    """D3 stale artifacts: a derived template whose derivation decided private
    frame bytes rests on entry-values-do-not-address-the-new-frame; a run
    with that switch off refuses it (never applies the stale summary)."""
    from synthetic import RCX, add, load, tmp
    from test_summary_templates import F, LIBRARY, MANGLED, THUNK, WIN64, _caller_writes, _derive
    from tdo_v2.image_info import ImageInfo, ImportedSymbol
    from tdo_v2.summary_store import load_external_models

    t = tmp(0x100)
    spilling = (FunctionBuilder(entry=F).sub_rsp(0x18).ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
                .ins(add(t, reg(RSP), const(8)), load(reg(0), t)).add_rsp(0x18).ret())
    path, refused, hand = _derive(tmp_path, spilling)
    assert not refused, refused
    models = load_external_models([hand, path], *WIN64)
    assert any("entry-values-do-not-address-the-new-frame" in entry.inherited
               for item in models.files for entry in item.entries if entry.template is not None)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())

    def client(on):
        return analyze_units(program_units(_caller_writes(THUNK)), image_info=info, external_models=models,
                             assume_entry_values_not_frame=on)["1:1000"]
    assert client(True).proven and not client(True).refused_models
    off = client(False)
    assert not off.proven and off.refused_models, off.refused_models


def test_an_arm64_leaf_is_certified_with_its_instruction_bytes():
    """Astra pc5 r1 P2-3: with the image's instruction bytes and the pinned PAC
    table the harness sees a proven, closed AArch64 leaf (not a blanket
    "pac-spec-unpinned")."""
    from synthetic import AARCH64, X0, copy

    leaf = FunctionBuilder(entry=MAIN, arch=AARCH64).ins(copy(reg(X0, 8), const(1, 8))).ret()
    results = analyze_units(program_units(leaf, registers=register_evidence(AARCH64)))
    nop = (0xD503201F).to_bytes(4, "little")
    certificates = acceptance.certificates_of(results, reader=lambda address, size: nop)
    (certificate,) = certificates.values()
    assert certificate.status == "proven" and certificate.closed
    unread = acceptance.certificates_of(results)
    assert not next(iter(unread.values())).closed


def test_off_only_functions_are_attributed_transitively():
    """Astra pc5 r2 P2-3: A (selected) -> B -> C, B and C only in the OFF run:
    both reached; an unrelated OFF-only D is not."""
    from types import SimpleNamespace

    def item(*targets):
        return SimpleNamespace(calls={f"c{index}": target for index, target in enumerate(targets)}, multi_calls={})
    blank = {kind: None for kind in acceptance.CLAIMS}
    on = {"A": dict(blank)}
    off = {"A": dict(blank), "B": dict(blank), "C": dict(blank), "D": dict(blank)}
    off_results = {"A": item("B"), "B": item("C"), "C": item("B"), "D": item()}
    from tdo_v2.premises import PremiseKind, PremiseRef

    premise = PremiseRef(PremiseKind.ASSUMPTION, LABEL, "0" * 64)
    producers = {"A": SimpleNamespace(premises=frozenset({premise}), published=frozenset({premise}))}
    found = acceptance.check(LABEL, on, off, {}, producers, off_results=off_results)
    assert found["off_only"] == 3 and found["off_only_unattributed"] == ["D"], found


def test_roots_are_grouped_by_the_whole_function_key():
    """Astra pc5 r2 P3: 1:1000 and 2:1000 are two functions."""
    from dataclasses import dataclass
    from types import SimpleNamespace

    @dataclass(frozen=True)
    class Root:
        function_space_id: int
        function_byte_offset: int
        label: str
        occurrence_ordinal: int

    roots = [Root(2, 0x1000, "x", 0)]
    item = SimpleNamespace(summary=None, normalized=None, proven={})
    found = acceptance.claims({"1:1000": item, "2:1000": item}, {}, roots)
    assert found["1:1000"]["roots"] != found["2:1000"]["roots"]


def test_external_models_withdraw_their_bindings_too():
    """Astra pc5 r2 P2-2: the OFF run takes neither the models nor the
    bindings; a bound-model premise selects external-models."""
    from types import SimpleNamespace
    from tdo_v2.premises import PremiseKind, PremiseRef

    binding = SimpleNamespace(binding_id="b", digest="d" * 64, rows=((0x1600, "m/E", None),),
                              models=SimpleNamespace(files=(SimpleNamespace(
                                  entries=(SimpleNamespace(label="bound-test/E"),), declares=()),)))
    withdrawn = acceptance.withdrawn_by("external-models", SimpleNamespace(files=()), (binding,))
    label = f"bound-model:b@{0x1600:#x}#{'d' * 12}"
    assert label in withdrawn and "bound-test/E" in withdrawn
    assert acceptance.selected("external-models", {PremiseRef(PremiseKind.MODEL, label, "0" * 64)}, withdrawn)
