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
