"""P-0 (owner 2026-11-25): the producer premises every Bundle run rests on --
decoder-matches-cpu, bundle-image-matches-file, producer-function-bodies-complete
-- are named in the registry and listed in every run, so a result never rests
on them silently (whether or not the Ghidra-independence work checks them)."""

from pathlib import Path

from synthetic import CODE_BASE, RCX, FunctionBuilder, analyze_summaries, boundary, const, copy, reg
from tdo_v2.assumptions import PRODUCER_PREMISES, REGISTRY, by_name, render_markdown, switches

SINK = CODE_BASE + 0xA00


def test_the_producer_premises_are_named_always_on_and_never_switches():
    assert PRODUCER_PREMISES == ("decoder-matches-cpu", "bundle-image-matches-file",
                                 "producer-function-bodies-complete")
    for name in PRODUCER_PREMISES:
        item = by_name(name)
        assert item.kind == "producer" and item.default is True
        assert item.flag is None and item.env is None and item.parameter is None
        assert item not in switches()
    assert [item.name for item in REGISTRY if item.kind == "producer"] == list(PRODUCER_PREMISES)


def test_the_generated_document_lists_them():
    text = render_markdown()
    for name in PRODUCER_PREMISES:
        assert f"| `{name}` | producer | on | - |" in text
    shipped = Path(__file__).resolve().parents[2] / "docs" / "assumptions.md"
    assert shipped.read_text(encoding="utf-8").replace("\r\n", "\n") == text


def test_every_summary_engine_run_lists_them_apart_from_the_assumptions():
    main = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(7))).call(SINK).add_rsp(0x28).ret()
    run = analyze_summaries([main, FunctionBuilder(entry=SINK).ret()], boundary({}, {"sink": 8}),
                            names={SINK: "sink"})
    assert run.producer_premises == PRODUCER_PREMISES
    assert not set(PRODUCER_PREMISES) & set(run.assumptions)
