"""2b-P part b: normalization records the named assumptions it decided under
(docs 25.91) -- policy switches stay inputs; use records say which were used."""

import pytest

from synthetic import RAX, FunctionBuilder, const, copy, load, program_units, reg, store
from tdo_v2.interprocedural import analyze_units

MAIN = 0x1000


def _uses(builder, **options):
    (result,) = analyze_units(program_units(builder), **options).values()
    return {name for name, stage, _ in result.normalized.premise_uses if stage == "normalize"}


def test_globals_disjoint_is_recorded_only_when_it_excluded_an_alias():
    main = FunctionBuilder(entry=MAIN).ins(store(const(0x4000), const(1, 8))).ret()
    assert "globals-disjoint-from-stack" in _uses(main, assume_globals_disjoint_from_stack=True)
    assert "globals-disjoint-from-stack" not in _uses(main, assume_globals_disjoint_from_stack=False)


def test_a_function_that_never_needs_it_does_not_list_it():
    main = FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).ret()
    assert _uses(main, assume_globals_disjoint_from_stack=True) == set()


def test_home_space_is_recorded_when_a_byte_above_entry_sp_was_decided_private():
    """Astra 2b-P r1: `store [entry RAX], 1; ret` is PROVEN only with the
    home space private -- its support must name it."""
    main = FunctionBuilder(entry=MAIN).ins(store(reg(RAX), const(1, 8))).ret()
    with_home = _uses(main, private_frame_above=0x28)
    without = _uses(main, private_frame_above=0)
    assert "win64-home-space-callee-private" in with_home
    assert "win64-home-space-callee-private" not in without


def test_a_readonly_image_read_is_recorded_where_it_was_read():
    """A pointer loaded from .rdata and dereferenced: its constant value came
    from the image (the read address is where)."""
    from synthetic import DATA_BASE, RBX, synthetic_image

    data = bytearray(4096)
    data[8:16] = (DATA_BASE + 0x20).to_bytes(8, "little")
    info, image = synthetic_image(data=bytes(data))
    main = FunctionBuilder(entry=MAIN).ins(load(reg(RAX), const(DATA_BASE + 8))).ins(load(reg(RBX), reg(RAX))).ret()
    (result,) = analyze_units(program_units(main), image_info=info, readonly_image=image).values()
    found = [(name, at) for name, stage, at in result.normalized.premise_uses
             if name == "readonly-image-data-is-constant"]
    assert found and all(at.endswith(f"{DATA_BASE + 8:x}") for _, at in found), result.normalized.premise_uses
    (plain,) = analyze_units(program_units(main), image_info=info).values()
    assert not any(name == "readonly-image-data-is-constant" for name, _, _ in plain.normalized.premise_uses)


def test_the_recording_image_notes_only_values_it_returned():
    from tdo_v2.normalize import _RecordingImage

    class Inner:
        size = 3

        def value(self, space, offset, size):
            return 7 if offset == 0x10 else None

    uses = []
    image = _RecordingImage(Inner(), uses)
    assert image.value(1, 0x10, 8) == 7 and image.value(1, 0x20, 8) is None and image.size == 3
    assert uses == ["1:10"]


@pytest.mark.parametrize("engine", ["sparse", "dense"])
def test_a_held_slot_above_entry_sp_records_the_home_space(engine, monkeypatch):
    """Astra 2b-P r1 P1: the held-slot decision admits [rsp + 8] = rsp only
    with the home space private; it keeps a below-SP read private, and a later
    escape keeps the return read from recording it incidentally."""
    from synthetic import RCX, RDI, RSP, R9, DATA_BASE, add, tmp

    if engine == "dense":
        monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", "dense")
    main = (FunctionBuilder(entry=MAIN)
            .ins(add(tmp(0x100), reg(RSP), const(8)), store(tmp(0x100), reg(RSP)))
            .ins(store(reg(RCX), reg(RDI)))
            .ins(add(tmp(0x108), reg(RSP), const(-8 & 0xFFFFFFFFFFFFFFFF)), load(reg(R9), tmp(0x108)))
            .ins(store(const(DATA_BASE + 0x10), reg(RSP)))
            .ret())
    with_home = _uses(main, private_frame_above=0x28)
    assert "win64-home-space-callee-private" in with_home, with_home
    assert "win64-home-space-callee-private" not in _uses(main, private_frame_above=0)
