"""P-0 (owner 2026-11-25): the base premises every Bundle run rests on -- five
about the Bundle's producer and one about the run time -- are named in the
registry, listed in every run (``EngineRun.base_premises``) and never a model's
or template's own label, so a result never rests on them silently (whether or
not the Ghidra-independence work checks them)."""

from pathlib import Path

import pytest
from synthetic import CODE_BASE, RCX, FunctionBuilder, analyze_summaries, boundary, const, copy, reg
from tdo_v2.assumptions import BASE_KINDS, BASE_PREMISES, REGISTRY, by_name, render_markdown, switches

SINK = CODE_BASE + 0xA00
EXPECTED = ("decoder-matches-cpu", "bundle-image-matches-file", "producer-program-facts-accurate",
            "producer-function-bodies-complete", "producer-listed-targets-complete",
            "image-code-unmodified-at-runtime")


def test_the_base_premises_are_named_always_on_and_never_switches():
    assert BASE_PREMISES == EXPECTED
    for name in BASE_PREMISES:
        item = by_name(name)
        assert item.kind in BASE_KINDS and item.default is True
        assert item.flag is None and item.env is None and item.parameter is None
        assert item not in switches()
    assert by_name("image-code-unmodified-at-runtime").kind == "runtime"
    assert [item.name for item in REGISTRY if item.kind in BASE_KINDS] == list(EXPECTED)


def test_the_generated_document_lists_them():
    text = render_markdown()
    for name in BASE_PREMISES:
        assert f"| `{name}` | {by_name(name).kind} | on | - |" in text
    shipped = Path(__file__).resolve().parents[2] / "docs" / "assumptions.md"
    assert shipped.read_text(encoding="utf-8").replace("\r\n", "\n") == text


def test_a_base_premise_is_never_a_model_or_template_label():
    """Astra P-0 r1 P1: a hand model declaring one was admitted and its label
    entered the inherited assumptions -- report-only means never a label."""
    from tdo_v2.summary_store import _label_problem

    for name in BASE_PREMISES:
        assert _label_problem(name) is not None
    assert _label_problem("globals-disjoint-from-stack") is None   # (control: a registry switch)


def test_every_summary_engine_run_lists_them_apart_from_the_assumptions():
    main = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(7))).call(SINK).add_rsp(0x28).ret()
    run = analyze_summaries([main, FunctionBuilder(entry=SINK).ret()], boundary({}, {"sink": 8}),
                            names={SINK: "sink"})
    assert run.base_premises == BASE_PREMISES
    assert not set(BASE_PREMISES) & set(run.assumptions)


def test_the_field_is_keyword_only_and_last():
    """Astra P-0 r1 P3: a positional caller must not bind it by accident."""
    from dataclasses import fields

    from tdo_v2.engine import EngineRun

    last = fields(EngineRun)[-1]
    assert last.name == "base_premises" and last.kw_only
    with pytest.raises(TypeError):
        EngineRun("d", "s", (), (), (), (), (), (), (), (), (), (), None, BASE_PREMISES)


def test_a_base_premise_is_never_a_resolvable_result_premise():
    """Astra P-0 r2: the support resolver must neither resolve the base
    premises nor fold them into its identity (report-only)."""
    from tdo_v2.premises import PremiseResolver, UnknownPremise, registry_premise

    for name in BASE_PREMISES:
        with pytest.raises(UnknownPremise):
            registry_premise(name)
    resolver = PremiseResolver()
    assert not set(BASE_PREMISES) & set(resolver._registry)
    registry_premise("globals-disjoint-from-stack")   # (control)
