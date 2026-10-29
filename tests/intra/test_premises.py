"""Stage 2b-P: the premise support contract (docs 25.91)."""

import dataclasses
import random

import pytest

from tdo_v2.premises import (ClaimType, EvidenceRef, PremiseKind, PremiseRef, PremiseUse, Support, UnknownPremise,
                             compose, declaration_premise, model_premise, provenance_closure, registry_premise,
                             resolve_label)


def _premise(kind, name):
    return PremiseRef(kind, name, "0" * 63 + str(len(name) % 10))


def test_a_registry_premise_changes_identity_when_its_row_changes(monkeypatch):
    from tdo_v2 import assumptions

    before = registry_premise("globals-disjoint-from-stack")
    rows = tuple(dataclasses.replace(row, statement=row.statement + " (edited)")
                 if row.name == "globals-disjoint-from-stack" else row for row in assumptions.REGISTRY)
    monkeypatch.setattr(assumptions, "REGISTRY", rows)
    after = registry_premise("globals-disjoint-from-stack")
    assert before.id == after.id and before.digest != after.digest


def test_a_declared_premise_is_bound_to_its_owning_model_file():
    catalog = {"crt:no-sbrk": ("crt", "the program never calls sbrk", "it does")}
    one = declaration_premise("crt:no-sbrk", catalog, {"crt": "a" * 64})
    two = declaration_premise("crt:no-sbrk", catalog, {"crt": "b" * 64})
    assert one.kind is PremiseKind.ASSUMPTION and one.digest != two.digest
    with pytest.raises(UnknownPremise):
        declaration_premise("crt:no-sbrk", catalog, {})


def test_an_edited_model_row_under_the_same_label_is_another_premise():
    label = "external-model:crt-win64/memcpy@v1"
    assert model_premise(label, "a" * 64) != model_premise(label, "b" * 64)
    assert model_premise(label, "a" * 64, {"writes": 1}) != model_premise(label, "a" * 64, {"writes": 2})


@pytest.mark.parametrize("label", ["no-such-assumption", "lib:undeclared", ""])
def test_an_unknown_label_fails_closed(label):
    with pytest.raises(UnknownPremise):
        resolve_label(label, catalog={}, file_digests={}, model_digests={})


def test_labels_resolve_by_source():
    assert resolve_label("globals-disjoint-from-stack").kind is PremiseKind.ASSUMPTION
    assert resolve_label("external-model:x/y@v1", model_digests={"external-model:x/y@v1": "c" * 64}).kind \
        is PremiseKind.MODEL
    catalog = {"lib:a": ("lib", "s", "f")}
    assert resolve_label("lib:a", catalog=catalog, file_digests={"lib": "d" * 64}).id == "lib:a"


def test_two_applications_are_two_uses():
    premise = registry_premise("globals-disjoint-from-stack")
    assert PremiseUse(premise, "normalize", "1:1000:2:STORE") != PremiseUse(premise, "normalize", "1:1004:2:STORE")
    with pytest.raises(ValueError):
        PremiseUse(premise, "somewhere", "x")


@pytest.mark.parametrize("claim,established", [
    (ClaimType.CONTINUATION, False), (ClaimType.CONTROL_CLOSURE, False), (ClaimType.REGISTER_DELTA, False),
    (ClaimType.BYTE_EQUALITY, True), (ClaimType.PROVENANCE, True)])
def test_a_link_premise_only_supports_data_claims(claim, established):
    support = Support(claim, "f", frozenset({_premise(PremiseKind.LINK, "L1")}))
    assert support.established is established


@pytest.mark.parametrize("claim", list(ClaimType))
def test_a_hypothesis_never_establishes_a_published_claim(claim):
    assert not Support(claim, "f", frozenset({_premise(PremiseKind.HYPOTHESIS, "scc")})).established


def test_obligations_and_composition():
    a = _premise(PremiseKind.ASSUMPTION, "a")
    callee = Support(ClaimType.CONTINUATION, "g", frozenset({a}), frozenset({EvidenceRef("graph", "g")}))
    caller = compose(ClaimType.CONTINUATION, "f", own={_premise(PremiseKind.MODEL, "m")}, via=(callee,))
    assert a in caller.premises and EvidenceRef("graph", "g") in caller.evidence and caller.established
    assert not caller.engine_proven
    assert not compose(ClaimType.CONTINUATION, "f", obligations=("debt",)).established
    broken = Support(ClaimType.CONTINUATION, "g", obligations=("x",))
    assert not compose(ClaimType.CONTINUATION, "f", via=(broken,)).established
    assert Support(ClaimType.CONTINUATION, "f").engine_proven
    assert caller.by_kind() == {"assumption": ["a"], "model": ["m"]}


def test_closure_unions_every_scc_member_and_its_dependencies():
    p = {name: _premise(PremiseKind.ASSUMPTION, name) for name in "abcde"}
    own = {"f": {p["a"]}, "g": {p["b"]}, "h": {p["c"]}, "leaf": {p["d"]}, "other": {p["e"]}}
    depends = {"f": ["g"], "g": ["h", "leaf"], "h": ["g"], "top": ["f"]}   # g <-> h a cycle
    result = provenance_closure(own, depends)
    assert result["g"] == result["h"] == frozenset({p["b"], p["c"], p["d"]})
    assert result["f"] == frozenset({p["a"], p["b"], p["c"], p["d"]})
    assert result["top"] == result["f"] and result["leaf"] == frozenset({p["d"]})
    assert result["other"] == frozenset({p["e"]})


def test_closure_matches_a_naive_fixed_point_on_random_graphs():
    rng = random.Random(7)
    for _ in range(200):
        nodes = [f"n{i}" for i in range(rng.randint(1, 12))]
        premises = [_premise(PremiseKind.ASSUMPTION, f"p{i}") for i in range(6)]
        own = {node: frozenset(rng.sample(premises, rng.randint(0, 2))) for node in nodes}
        depends = {node: rng.sample(nodes, rng.randint(0, min(3, len(nodes)))) for node in nodes}
        naive = {node: set(own[node]) for node in nodes}
        changed = True
        while changed:
            changed = False
            for node in nodes:
                for target in depends[node]:
                    if not naive[target] <= naive[node]:
                        naive[node] |= naive[target]
                        changed = True
        # the closure adds every SCC member's own premises to the others (conservative):
        # a superset of reachability, equal on acyclic graphs
        result = provenance_closure(own, depends)
        for node in nodes:
            assert naive[node] <= result[node]
            reachable = {node}
            pending = [node]
            while pending:
                for target in depends[pending.pop()]:
                    if target not in reachable:
                        reachable.add(target)
                        pending.append(target)
            assert result[node] == frozenset().union(*(own[item] for item in reachable))


def test_compose_keeps_an_iterator_of_supports():
    """Astra 2b-P r1 P2: an iterator ``via`` must not be exhausted before kept."""
    child = Support(ClaimType.CONTINUATION, "g", obligations=("unresolved call",))
    parent = compose(ClaimType.CONTINUATION, "f", via=iter((child,)))
    assert parent.via == (child,) and not parent.established


def _models(digest="a" * 64, statement="s"):
    from types import SimpleNamespace

    entry = SimpleNamespace(label="external-model:crt/memcpy@v1", name="memcpy")
    item = SimpleNamespace(file_id="crt", digest=digest, entries=(entry,),
                           declares=(("crt:no-sbrk", statement, "f"),))
    return SimpleNamespace(files=(item,))


def test_the_resolver_authenticates_against_loaded_inputs():
    from tdo_v2.premises import PremiseResolver
    from tdo_v2.pcodeop_models import PcodeOpModel

    lock = PcodeOpModel("x86-markers", 1, frozenset({("x86:LE:64:default", 1, 0)}), {17: "LOCK"})
    resolver = PremiseResolver(model_sets=(_models(),), pcodeop_models=(lock,))
    assert resolver.resolve("globals-disjoint-from-stack").kind is PremiseKind.ASSUMPTION
    assert resolver.resolve("external-model:crt/memcpy@v1").kind is PremiseKind.MODEL
    assert resolver.resolve("crt:no-sbrk").kind is PremiseKind.ASSUMPTION
    assert resolver.resolve("pcodeop-model:x86-markers/LOCK@v1").kind is PremiseKind.MODEL
    for label in ("external-model:crt/other@v1", "pcodeop-model:x86-markers/UNLOCK@v1",
                  "lifecycle-contract:x@v1#" + "0" * 64, "lib:undeclared"):
        with pytest.raises(UnknownPremise):
            resolver.resolve(label)   # a prefix never authenticates
    found, unknown = resolver.resolve_all(["globals-disjoint-from-stack", "lib:undeclared"])
    assert len(found) == 1 and unknown == ("lib:undeclared",)


def test_an_edited_input_under_the_same_label_changes_identity():
    from tdo_v2.premises import PremiseResolver

    one = PremiseResolver(model_sets=(_models("a" * 64),))
    two = PremiseResolver(model_sets=(_models("b" * 64),))
    edited = PremiseResolver(model_sets=(_models("a" * 64, statement="edited"),))
    assert one.identity != two.identity and one.identity != edited.identity
    assert one.resolve("external-model:crt/memcpy@v1") != two.resolve("external-model:crt/memcpy@v1")
    assert one.resolve("crt:no-sbrk") != edited.resolve("crt:no-sbrk")


def test_a_contract_label_must_carry_the_loaded_contracts_digest():
    from types import SimpleNamespace
    from tdo_v2.premises import PremiseResolver

    good = "lifecycle-contract:alloc@v1#" + "c" * 64
    contract = SimpleNamespace(label=good, canonical_digest="c" * 64)
    resolver = PremiseResolver(lifecycle_contracts=(contract,))
    assert resolver.resolve(good).kind is PremiseKind.MODEL
    with pytest.raises(UnknownPremise):
        resolver.resolve("lifecycle-contract:alloc@v1#" + "d" * 64)


def test_the_resolver_snapshots_the_registry(monkeypatch):
    """Astra pc1 r1 P1: a registry edit after construction neither changes an
    existing resolver's answers nor escapes a new resolver's identity."""
    from tdo_v2 import assumptions
    from tdo_v2.premises import PremiseResolver

    before = PremiseResolver()
    answer = before.resolve("globals-disjoint-from-stack")
    rows = tuple(dataclasses.replace(row, statement=row.statement + " (edited)")
                 if row.name == "globals-disjoint-from-stack" else row for row in assumptions.REGISTRY)
    monkeypatch.setattr(assumptions, "REGISTRY", rows)
    assert before.resolve("globals-disjoint-from-stack") == answer
    assert PremiseResolver().identity != before.identity


def test_binding_rows_are_authenticated():
    from types import SimpleNamespace
    from tdo_v2.premises import PremiseResolver

    binding = SimpleNamespace(binding_id="tv2", digest="e" * 64, executable_sha256="f" * 64,
                              rows=((0x4e10, "m1", None),), models=None)
    resolver = PremiseResolver(bindings=(binding,))
    assert resolver.resolve("bound-model:tv2@0x4e10#" + "e" * 12).kind is PremiseKind.MODEL
    for label in ("bound-model:tv2@0x4e14#" + "e" * 12, "bound-model:tv2@0x4e10#" + "0" * 12):
        with pytest.raises(UnknownPremise):
            resolver.resolve(label)


def test_the_accessor_wrapper_needs_a_loaded_model_entry():
    from tdo_v2.premises import PremiseResolver

    resolver = PremiseResolver(model_sets=(_models(),))
    assert resolver.resolve("accessor-state-preserved-by:external-model:crt/memcpy@v1").kind is PremiseKind.MODEL
    for label in ("accessor-state-preserved-by:globals-disjoint-from-stack",
                  "accessor-state-preserved-by:accessor-state-preserved-by:external-model:crt/memcpy@v1"):
        with pytest.raises(UnknownPremise):
            resolver.resolve(label)


def test_a_trap_only_pcode_model_is_part_of_the_identity():
    from tdo_v2.pcodeop_models import PcodeOpModel
    from tdo_v2.premises import PremiseResolver

    language = frozenset({("x86:LE:64:default", 1, 0)})
    one = PremiseResolver(pcodeop_models=(PcodeOpModel("t", 1, language, {}, {41: frozenset({3})}),))
    two = PremiseResolver(pcodeop_models=(PcodeOpModel("t", 1, language, {}, {41: frozenset({4})}),))
    assert len({one.identity, two.identity, PremiseResolver().identity}) == 3


def test_resolver_inputs_may_be_iterators():
    """Astra pc1 r2 P2-2: a bindings iterator read twice lost every row."""
    from types import SimpleNamespace
    from tdo_v2.premises import PremiseResolver

    binding = SimpleNamespace(binding_id="tv2", digest="e" * 64, executable_sha256="f" * 64,
                              rows=((0x4e10, "m1", None),), models=_models())
    from_iter = PremiseResolver(bindings=iter((binding,)), model_sets=iter(()))
    from_tuple = PremiseResolver(bindings=(binding,))
    assert from_iter.identity == from_tuple.identity
    assert from_iter.resolve("bound-model:tv2@0x4e10#" + "e" * 12).kind is PremiseKind.MODEL


def test_a_pcode_label_exported_by_two_models_is_refused():
    """Astra pc1 r2 P2-1: order must not choose between two exporters."""
    from tdo_v2.pcodeop_models import PcodeOpModel
    from tdo_v2.premises import PremiseResolver

    language = frozenset({("x86:LE:64:default", 1, 0)})
    one = PcodeOpModel("x86-markers", 1, language, {17: "LOCK"}, {41: frozenset({3})})
    two = PcodeOpModel("x86-markers", 1, language, {17: "LOCK"}, {41: frozenset({4})})
    forward, backward = PremiseResolver(pcodeop_models=(one, two)), PremiseResolver(pcodeop_models=(two, one))
    assert forward.identity == backward.identity
    for resolver in (forward, backward):
        with pytest.raises(UnknownPremise):
            resolver.resolve("pcodeop-model:x86-markers/LOCK@v1")
    assert PremiseResolver(pcodeop_models=(one,)).resolve("pcodeop-model:x86-markers/LOCK@v1").kind \
        is PremiseKind.MODEL
