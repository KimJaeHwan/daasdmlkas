"""Linking (``tdo_v2.linking``, design section 24): the coordinator with a
fake Ghidra provider. Coverage check, hand model first, one template per
called export, the cache (hits, stored semantic refusals, retried
infrastructure and budget failures, profile changes, refresh), the library's
stack evidence, the check before the run, and a linked template applied by
the engine exactly as the function's own body would be."""

import json
import struct
from pathlib import Path

import pytest

from synthetic import NO_CALLBACKS, RAX, RCX, RDX, RSI, FunctionBuilder, copy, program_units, reg, store
from test_summary_templates import (
    F, IMAGE, LIBRARY, MANGLED, POINTS, THUNK, WIN64, _caller_writes, _effect, _every_constant_relocates, _hand_file,
    _views,
)
from tdo_v2.image_info import ExportedSymbol, ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.linking import (
    BUDGET, INFRASTRUCTURE, SEMANTIC, LinkError, Linker, LinkTarget, ProviderError, refusal_class_of, split_templates,
)
from tdo_v2.pe_exports import read_pe_exports
from tdo_v2.relative_memory import ImageBaseTracking
from tdo_v2.stack_evidence import EXCEPTIONS
from tdo_v2.summary_store import load_external_models
from tdo_v2.summary_templates import Refusal, build_file

DATA = "?GData@@3HA"
FORWARD = "?Fw@@YAXXZ"
SECOND = "?F2@@YAXXZ"
BROKEN = "?F3@@YAXXZ"
UNCALLED = "?F4@@YAXXZ"


def _pe(path: Path, exports) -> Path:
    """A PE32+ DLL: .text (executable, RVA 0x1000), .rdata (RVA 0x2000) with
    the export directory. ``exports``: (name or None, "code" | "data" |
    "forwarder:<text>") in ordinal order from base 1."""
    text_rva, rdata_rva, size = 0x1000, 0x2000, 0x1000
    names = [(index, name) for index, (name, _) in enumerate(exports) if name is not None]
    names.sort(key=lambda row: row[1].encode())
    blob = bytearray(size)
    directory, functions = 0, 0x40
    name_table = functions + 4 * len(exports)
    ordinals = name_table + 4 * len(names)
    strings = ordinals + 2 * len(names)
    string_rvas = {}
    for text in [name for _, name in names] + [kind[10:] for _, kind in exports if kind.startswith("forwarder:")]:
        string_rvas[text] = rdata_rva + strings
        blob[strings:strings + len(text) + 1] = text.encode() + b"\0"
        strings += len(text) + 1
    export_size = strings
    for index, (name, kind) in enumerate(exports):
        rva = text_rva + 0x10 * index if kind == "code" else \
            rdata_rva + 0x800 + 8 * index if kind == "data" else string_rvas[kind[10:]]
        struct.pack_into("<I", blob, functions + 4 * index, rva)
    for slot, (index, name) in enumerate(names):
        struct.pack_into("<I", blob, name_table + 4 * slot, string_rvas[name])
        struct.pack_into("<H", blob, ordinals + 2 * slot, index)
    struct.pack_into("<IIHHIIIIIII", blob, directory, 0, 0, 0, 0, 0, 1, len(exports), len(names),
                     rdata_rva + functions, rdata_rva + name_table, rdata_rva + ordinals)
    header = bytearray(0x400)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x44, 0x8664, 2, 0, 0, 0, 240, 0x2022)
    optional = 0x58
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<Q", header, optional + 24, 0x180000000)
    struct.pack_into("<II", header, optional + 112, rdata_rva, export_size)
    table = optional + 240
    for index, (name, rva, characteristics) in enumerate(((b".text", text_rva, 0x60000020),
                                                         (b".rdata", rdata_rva, 0x40000040))):
        struct.pack_into("<8sIIII", header, table + 40 * index, name, size, rva, size, 0x400 + size * index)
        struct.pack_into("<I", header, table + 40 * index + 36, characteristics)
    path.write_bytes(bytes(header) + bytes(size) + bytes(blob))
    return path


EXPORTS = ((MANGLED, "code"), (DATA, "data"), (FORWARD, "forwarder:OTHER.Fw"), (SECOND, "code"),
           (BROKEN, "code"), (UNCALLED, "code"), (None, "code"))
BODY = FunctionBuilder(entry=F).ins(copy(reg(RAX), reg(RCX))).ins(store(reg(RDX), reg(RSI))).ret()


def _evidence_file(path, sha256, switches=()):
    raw = {"format": "tdo-v2-stack-switch-evidence", "version": 1, "detector": "stack-switch-coefficient-v3",
           "executable_sha256": sha256, "program": f"/libs/{LIBRARY}", "language": "x86:LE:64:default",
           "stack_pointer": "RSP", "functions_scanned": 10, "instructions_scanned": 100,
           "instructions_outside_functions": 0, "call_preserved": ["RBX", "RBP", "R12", "R13", "R14", "R15"],
           "exceptions": list(EXCEPTIONS),
           "switches": [{"function": "180001000", "instruction": address, "ordinal": 1, "opcode": "COPY"}
                        for address in switches]}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class FakeProvider:
    def __init__(self, sha256, fail=None, switches=(), version="test"):
        self.sha256, self.fail, self.switches, self.version = sha256, fail, switches, version
        self.exports, self.scans = [], 0

    def identity(self):
        return {"ghidra": self.version, "stack_scanner": "scanner-1"}

    def stack_evidence(self, target, path):
        self.scans += 1
        return _evidence_file(path, self.sha256, self.switches)

    def export(self, target, entries, space_id):
        if self.fail is not None:
            raise self.fail
        self.exports.append(sorted(name for name, _ in entries))
        return Path("generation")


class FakeDeriver:
    """Derives F (MANGLED) from BODY with the models and settings it is
    given, as derive_library(per_export=True); refuses SECOND (semantic) and
    the names in ``refusals``; leaves BROKEN out of the Bundle."""

    def __init__(self, sha256, refusals=None):
        self.sha256, self.refusals, self.calls = sha256, dict(refusals or {}), []

    def __call__(self, generation, library, names, *, file_id, models, pcodeops, stack_evidence,
                 private_frame_above, traps, assume_globals_disjoint, direction_flag, per_export, log,
                 import_slots=False, entry_values_not_frame=True, same_result=False, accessor_separate=False,
                 opaque_no_stack=True, registered_handlers=True, accessor_private_state=False, pre_escape=True,
                 model_assumptions_off=(), catalog_models=(), opaque_restores_sp=True):
        assert per_export
        self.calls.append({"names": sorted(names), "private_frame_above": private_frame_above,
                           "globals": assume_globals_disjoint, "direction_flag": direction_flag,
                           "same_result": same_result, "accessor_separate": accessor_separate,
                           "evidence": [Path(item).name for item in stack_evidence]})
        files, refused = {}, {}
        for name in names:
            if name in self.refusals:
                refused[name] = self.refusals[name]
            elif name == SECOND:
                refused[name] = "a crossing the template cannot name"
            elif name == MANGLED:
                info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, F, MANGLED, True),), ())
                with ImageBaseTracking((IMAGE,), _every_constant_relocates) as found:
                    results = analyze_units(program_units(BODY), image_info=info, external_models=models,
                                            pcodeop_models=pcodeops, own_library=library,
                                            private_frame_above=private_frame_above,
                                            assume_debug_break_traps_do_not_return=traps,
                                            assume_direction_flag_clear=direction_flag,
                                            assume_entry_values_not_frame=entry_values_not_frame,
                                            assume_opaque_callees_leave_no_stack_addresses=opaque_no_stack,
                                            assume_same_result_functions=same_result,
                                            assume_accessor_result_separate=accessor_separate)
                raw, _ = build_file(results, [(f"1:{F:x}", MANGLED, [MANGLED])], file_id=file_id, version=1,
                                    library=library, external_models=models, pcodeop_models=pcodeops,
                                    private_frame_above=private_frame_above, base_dependent=found, traps=traps,
                                    catalog_models=catalog_models)
                raw["source"]["sha256"] = self.sha256
                files[name] = raw
        return files, refused, [name for name in names if name == BROKEN]


def _imports(*names):
    return tuple(ImportedSymbol(LIBRARY, name.strip("?").split("@")[0], name, (), ((1, THUNK + 0x10 * index),))
                 for index, name in enumerate(names))


def _hand_library_file(directory):
    """A hand model for one of the library's own exports (UNCALLED)."""
    raw = {"format_version": 1, "kind": "declared", "id": "synth-lib-hand", "version": 1,
           "language_id": WIN64[0], "abi_tag": WIN64[1], "libraries": [LIBRARY],
           "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
           "entries": [{"name": "F4", "original_names": [UNCALLED], "registers": [], "memory": [],
                        **NO_CALLBACKS, "other_memory": "preserved"}]}
    path = Path(directory) / "lib_hand.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _setup(tmp_path, *, imports=None, exports=EXPORTS):
    dll = _pe(tmp_path / "synth.dll", exports)
    imported = _imports(*(imports or (MANGLED, DATA, FORWARD, SECOND, BROKEN, UNCALLED)))
    info = ImageInfo("synthetic", (), imported, (), ())
    hand = tmp_path / "hand"
    hand.mkdir(exist_ok=True)
    models = load_external_models([_hand_library_file(hand)], *WIN64)
    return dll, read_pe_exports(dll).sha256, info, models


def _called(monkeypatch, info, names):
    import tdo_v2.interprocedural as interprocedural

    symbols = {symbol.original_name: symbol for symbol in info.imports}
    monkeypatch.setattr(interprocedural, "import_call_sites",
                        lambda unit, image_info, *rest: {f"call{index}": symbols[name] for index, name in enumerate(names)})


UNIT = program_units(FunctionBuilder().ret())[0]


def _link(tmp_path, info, models, provider, deriver, *, units=None, private_frame_above=0, refresh=False,
          dry_run=False, globals_disjoint=True, direction_flag=True, traps=True, same_result=False,
          accessor_separate=False, model_assumptions_off=(), catalog_models=()):
    linker = Linker([LinkTarget(LIBRARY, tmp_path / "synth.dll")], tmp_path / "cache", provider, deriver,
                    refresh=refresh, dry_run=dry_run, log=lambda line: None)
    linked, evidence = linker(units or [UNIT], info, external_models=models, pcodeop_models=None,
                              private_frame_above=private_frame_above, traps=traps,
                              globals_disjoint=globals_disjoint, direction_flag=direction_flag,
                              same_result=same_result, accessor_separate=accessor_separate,
                              model_assumptions_off=model_assumptions_off, catalog_models=catalog_models)
    return linker.report, linked, evidence


def _rows(report):
    return {row.name: (row.status, row.refusal_class) for row in report.rows}


def test_pe_exports_reads_names_ordinals_and_kinds(tmp_path):
    exports = read_pe_exports(_pe(tmp_path / "x.dll", EXPORTS))
    by_name = exports.by_name()
    assert exports.image_base == 0x180000000 and exports.machine == 0x8664
    assert by_name[MANGLED].kind == "code" and by_name[MANGLED].rva == 0x1000 and by_name[MANGLED].ordinal == 1
    assert by_name[DATA].kind == "data"
    assert by_name[FORWARD].kind == "forwarder" and by_name[FORWARD].forward == "OTHER.Fw"
    assert exports.by_ordinal()[7].name is None and exports.by_ordinal()[7].kind == "code"


def test_another_dll_is_refused_before_anything_is_scanned_or_derived(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path, exports=EXPORTS[:3])
    _called(monkeypatch, info, [MANGLED])
    provider = FakeProvider(sha)
    with pytest.raises(LinkError, match="not the library the program was built against"):
        _link(tmp_path, info, models, provider, FakeDeriver(sha))
    assert provider.exports == [] and provider.scans == 0


def test_a_library_the_program_does_not_import_is_an_error(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    info = ImageInfo("synthetic", (), (), (), ())
    _called(monkeypatch, info, [])
    with pytest.raises(LinkError, match="imports nothing"):
        _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))


def test_a_dll_of_another_machine_is_refused(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    data = bytearray(dll.read_bytes())
    data[0x44:0x46] = (0x14C).to_bytes(2, "little")
    dll.write_bytes(bytes(data))
    _called(monkeypatch, info, [MANGLED])
    with pytest.raises(LinkError, match="PE machine 0x14c"):
        _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))


def test_rows_cache_and_refusal_classes(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED, DATA, FORWARD, SECOND, BROKEN, UNCALLED, MANGLED])
    provider, deriver = FakeProvider(sha), FakeDeriver(sha)
    report, linked, evidence = _link(tmp_path, info, models, provider, deriver)
    assert _rows(report) == {
        MANGLED: ("derived", None), DATA: ("data", None), FORWARD: ("forwarder", None),
        SECOND: ("refused", SEMANTIC), BROKEN: ("refused", INFRASTRUCTURE),
        UNCALLED: ("model", None),     # hand model first: never derived
    }
    assert provider.exports == [sorted([MANGLED, SECOND, BROKEN])] and provider.scans == 1
    assert deriver.calls[0]["evidence"] and deriver.calls[0]["globals"] and len(evidence) == 1
    found = linked.lookup(_imports(MANGLED)[0])
    assert found is not None and found[0].file_id.startswith("link-synth-dll-") and found[1].template is not None

    # the second run: everything from the cache
    provider2 = FakeProvider(sha)
    report2, linked2, evidence2 = _link(tmp_path, info, models, provider2, FakeDeriver(sha))
    assert _rows(report2)[MANGLED] == ("cached", None) and _rows(report2)[SECOND] == ("refused", SEMANTIC)
    assert _rows(report2)[BROKEN] == ("refused", INFRASTRUCTURE)   # stored: the same Bundle would miss it again
    assert provider2.exports == [] and provider2.scans == 0 and evidence2 == evidence

    # another analysis setting is another profile: everything derived again, with it
    for change in ({"private_frame_above": 0x28}, {"globals_disjoint": False}, {"direction_flag": False},
                   {"same_result": True}, {"accessor_separate": True}):
        provider3, deriver3 = FakeProvider(sha), FakeDeriver(sha)
        report3, _, _ = _link(tmp_path, info, models, provider3, deriver3, **change)
        assert provider3.exports == [sorted([MANGLED, SECOND, BROKEN])], change
        call = deriver3.calls[0]
        assert call["private_frame_above"] == change.get("private_frame_above", 0)
        assert call["globals"] == change.get("globals_disjoint", True)
        assert call["direction_flag"] == change.get("direction_flag", True)
        assert call["same_result"] == change.get("same_result", False)
        assert call["accessor_separate"] == change.get("accessor_separate", False)

    # --link-refresh ignores the cache and scans the library again
    provider4 = FakeProvider(sha)
    _link(tmp_path, info, models, provider4, FakeDeriver(sha), refresh=True)
    assert provider4.exports == [sorted([MANGLED, SECOND, BROKEN])] and provider4.scans == 1


def test_a_refresh_refusal_replaces_the_stored_template(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))
    report, linked, _ = _link(tmp_path, info, models, FakeProvider(sha),
                              FakeDeriver(sha, {MANGLED: "depends on the library's load address"}), refresh=True)
    assert _rows(report) == {MANGLED: ("refused", SEMANTIC)}
    report, linked, _ = _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))
    assert _rows(report) == {MANGLED: ("refused", SEMANTIC)} and linked.lookup(_imports(MANGLED)[0]) is None
    # a refresh failing for another reason keeps nothing older either
    report, linked, _ = _link(tmp_path, info, models, FakeProvider(sha, fail=ProviderError("Ghidra died")),
                              FakeDeriver(sha), refresh=True)
    provider = FakeProvider(sha)
    _link(tmp_path, info, models, provider, FakeDeriver(sha))
    assert provider.exports == [[MANGLED]]


@pytest.mark.parametrize("reason, refusal_class", [(Refusal("not analyzed", INFRASTRUCTURE), INFRASTRUCTURE),
                                                   (Refusal("1:800: recursion without a verified fixpoint", BUDGET),
                                                    BUDGET)])
def test_derivation_refusals_are_stored_with_their_class(tmp_path, monkeypatch, reason, refusal_class):
    """The same Bundle and profile give the same verdict: not re-exported
    every run; --link-refresh retries."""
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha, {MANGLED: reason}))
    assert _rows(report) == {MANGLED: ("refused", refusal_class)}
    provider = FakeProvider(sha)
    report, _, _ = _link(tmp_path, info, models, provider, FakeDeriver(sha))
    assert provider.exports == [] and _rows(report) == {MANGLED: ("refused", refusal_class)}
    provider = FakeProvider(sha)
    report, _, _ = _link(tmp_path, info, models, provider, FakeDeriver(sha), refresh=True)
    assert provider.exports == [[MANGLED]] and _rows(report) == {MANGLED: ("derived", None)}


def test_a_failed_derivation_of_one_export_is_never_stored(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha),
                         FakeDeriver(sha, {MANGLED: Refusal("derivation failed: KeyError", "transient")}))
    assert _rows(report) == {MANGLED: ("refused", INFRASTRUCTURE)}
    provider = FakeProvider(sha)
    _link(tmp_path, info, models, provider, FakeDeriver(sha))
    assert provider.exports == [[MANGLED]]


def test_refresh_clears_every_profile_of_the_build(tmp_path, monkeypatch):
    """A re-analysis may change any template: after --link-refresh no older
    one is used, under any profile."""
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))                          # globals on
    _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha), globals_disjoint=False)  # globals off
    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha),
                         FakeDeriver(sha, {MANGLED: "depends on the library's load address"}),
                         globals_disjoint=False, refresh=True)
    assert _rows(report) == {MANGLED: ("refused", SEMANTIC)}
    provider = FakeProvider(sha)
    report, linked, _ = _link(tmp_path, info, models, provider, FakeDeriver(sha))               # globals on again
    assert provider.exports == [[MANGLED]] and _rows(report) == {MANGLED: ("derived", None)}


def test_build_file_refusals_carry_their_kind():
    from tdo_v2.summary_templates import TemplateRefused

    assert TemplateRefused("x").kind == SEMANTIC and TemplateRefused("x", BUDGET).kind == BUDGET
    assert refusal_class_of(Refusal("not analyzed", INFRASTRUCTURE)) == INFRASTRUCTURE
    assert refusal_class_of("not analyzed") == SEMANTIC   # classified by kind, never by wording


def test_library_evidence_with_a_switch_turns_the_assumption_off_for_the_derivation(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    deriver = FakeDeriver(sha)
    _, _, evidence = _link(tmp_path, info, models, FakeProvider(sha, switches=["180001234"]), deriver)
    assert deriver.calls[0]["globals"] is False and len(evidence) == 1   # the run withdraws it too


def test_evidence_joins_the_run_even_when_nothing_is_derived(tmp_path, monkeypatch):
    """The library's code runs whenever it is linked: hand-modeled-only and
    refusal-only links still bring its stack evidence."""
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [UNCALLED])
    provider = FakeProvider(sha)
    report, _, evidence = _link(tmp_path, info, models, provider, FakeDeriver(sha))
    assert _rows(report) == {UNCALLED: ("model", None)} and provider.scans == 1 and len(evidence) == 1
    # a dry run uses a scan already made, and never launches one
    provider = FakeProvider(sha, version="other")
    report, _, evidence = _link(tmp_path, info, models, provider, FakeDeriver(sha), dry_run=True)
    assert provider.scans == 0 and evidence == ()


def test_a_scan_of_another_binary_is_no_evidence(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    deriver = FakeDeriver(sha)
    report, _, evidence = _link(tmp_path, info, models, FakeProvider("0" * 64), deriver)
    assert evidence == () and deriver.calls[0]["evidence"] == []
    assert any("NO stack evidence" in line for line in report.lines)


def test_provider_failures_are_never_stored(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    report, linked, _ = _link(tmp_path, info, models, FakeProvider(sha, fail=ProviderError("Ghidra died")),
                              FakeDeriver(sha))
    assert _rows(report) == {MANGLED: ("refused", INFRASTRUCTURE)} and report.template_files == []
    assert linked.lookup(_imports(MANGLED)[0]) is None
    provider = FakeProvider(sha)
    report, _, _ = _link(tmp_path, info, models, provider, FakeDeriver(sha))
    assert provider.exports == [[MANGLED]] and _rows(report) == {MANGLED: ("derived", None)}


def test_a_bundle_of_another_build_is_refused(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver("0" * 64))
    assert _rows(report) == {MANGLED: ("refused", INFRASTRUCTURE)} and report.template_files == []
    assert not list((tmp_path / "cache").rglob("templates/*.json"))


def test_a_corrupt_cache_file_is_a_miss(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))
    (template,) = report.template_files
    Path(template).write_text("{not json", encoding="utf-8")
    provider = FakeProvider(sha)
    report, linked, _ = _link(tmp_path, info, models, provider, FakeDeriver(sha))
    assert provider.exports == [[MANGLED]] and linked.lookup(_imports(MANGLED)[0]) is not None


def test_an_edited_cache_file_is_a_miss(tmp_path, monkeypatch):
    """Valid JSON, but not the file the linker stored (``"summary": {}``)."""
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))
    (template,) = report.template_files
    raw = json.loads(Path(template).read_text(encoding="utf-8"))
    raw["entries"][0]["summary"] = {}
    Path(template).write_text(json.dumps(raw), encoding="utf-8")
    provider, deriver = FakeProvider(sha), FakeDeriver(sha)
    report, _, _ = _link(tmp_path, info, models, provider, deriver)
    assert provider.exports == [[MANGLED]] and _rows(report) == {MANGLED: ("derived", None)}


def test_an_unusable_template_is_reported_and_left_out(tmp_path, monkeypatch):
    """Checked before the run as the engine checks it at the call: a
    template the run would refuse is never claimed as linked."""
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])

    class Stale(FakeDeriver):   # derives for another language version than the run's
        def __call__(self, *args, **kwargs):
            files, refused, missing = super().__call__(*args, **kwargs)
            for raw in files.values():
                raw["source"]["language"]["minor"] += 1
            return files, refused, missing

    report, linked, _ = _link(tmp_path, info, models, FakeProvider(sha), Stale(sha), private_frame_above=0x28)
    assert _rows(report) == {MANGLED: ("unusable", None)} and report.template_files == []
    assert linked.lookup(_imports(MANGLED)[0]) is None


def test_a_template_resting_on_a_switched_off_model_assumption_is_unusable(tmp_path, monkeypatch):
    """A label a model file declares, switched off for the run: the linked
    template resting on it is refused at preflight (and the profile, so the
    cache, differs); one a binding's model file declares resolves too
    (``catalog_models``), never an unknown-label error (docs 25.74)."""
    dll, sha, info, _ = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    declaration = [{"id": "x", "statement": "s", "fails_when": "f"}]
    hand = tmp_path / "hand" / "lib_hand.json"
    hand.write_text(json.dumps({**json.loads(hand.read_text(encoding="utf-8")),
                                "declares_assumptions": declaration}), encoding="utf-8")
    models = load_external_models([hand], *WIN64)
    bound = tmp_path / "bound"
    bound.mkdir()
    (bound / "b.json").write_text(json.dumps({
        "format_version": 1, "kind": "declared", "id": "bound-decl", "version": 1, "language_id": WIN64[0],
        "abi_tag": WIN64[1], "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [], "entries": [],
        "declares_assumptions": declaration}), encoding="utf-8")
    binding_models = load_external_models([bound / "b.json"], *WIN64)

    class Resting(FakeDeriver):
        def __call__(self, *args, **kwargs):
            files, refused, missing = super().__call__(*args, **kwargs)
            for raw in files.values():
                raw["source"]["assumptions"] += ["synth-lib-hand:x", "bound-decl:x"]
            return files, refused, missing

    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha), Resting(sha), catalog_models=(binding_models,))
    assert _rows(report) == {MANGLED: ("derived", None)}
    for off in ("synth-lib-hand:x", "bound-decl:x"):
        report, linked, _ = _link(tmp_path, info, models, FakeProvider(sha), Resting(sha),
                                  model_assumptions_off=(off,), catalog_models=(binding_models,))
        assert _rows(report) == {MANGLED: ("unusable", None)} and report.template_files == []
    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha), Resting(sha))   # bound-decl:x undeclared
    assert _rows(report) == {MANGLED: ("unusable", None)}


def test_an_ordinal_import_is_matched_by_ordinal_and_not_linked(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path, imports=(MANGLED, "Ordinal_7", "Ordinal_1"))
    _called(monkeypatch, info, ["Ordinal_7", "Ordinal_1"])   # Ordinal_1 is MANGLED's ordinal
    provider = FakeProvider(sha)
    report, _, _ = _link(tmp_path, info, models, provider, FakeDeriver(sha))
    assert _rows(report) == {"Ordinal_7": ("ordinal", None), "Ordinal_1": ("ordinal", None)}
    assert provider.exports == []
    dll, sha, info, models = _setup(tmp_path, imports=(MANGLED, "Ordinal_9"))
    with pytest.raises(LinkError, match="does not export"):
        _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))


def test_a_dry_run_without_evidence_does_not_consult_the_cache(tmp_path, monkeypatch):
    dll, sha, info, models = _setup(tmp_path)
    _called(monkeypatch, info, [MANGLED])
    _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha))
    report, _, _ = _link(tmp_path, info, models, FakeProvider(sha), FakeDeriver(sha), dry_run=True)
    assert _rows(report) == {MANGLED: ("cached", None)}
    evidence_files = list((tmp_path / "cache").rglob("stack-*.json"))
    for path in evidence_files:
        path.write_text("{broken", encoding="utf-8")
    provider = FakeProvider(sha)
    report, _, evidence = _link(tmp_path, info, models, provider, FakeDeriver(sha), dry_run=True)
    assert _rows(report) == {MANGLED: ("pending", None)} and evidence == () and provider.scans == 0
    assert all(path.is_file() for path in evidence_files)   # a dry run deletes nothing


def test_split_templates_gives_one_file_per_export_with_unique_ids():
    raw = {"id": "x", "source": {}, "entries": [{"name": "a"}, {"name": "b"}]}
    files = split_templates(raw, "UNREALEDITOR-CORE.DLL", "ab" * 32)
    assert [entry["name"] for entry in files["a"]["entries"]] == ["a"]
    assert files["a"]["id"] != files["b"]["id"] and files["a"]["id"].startswith("link-unrealeditor-core-dll-abab")


def test_a_linked_template_is_applied_as_the_body_would_be(tmp_path):
    """End to end through the engine: the client calls F through its import
    thunk; the linked template gives the same effect and slices as F's own
    body in the client's Bundle. A hand model of the same name for another
    library does not keep it out (models match by library and name)."""
    dll = _pe(tmp_path / "synth.dll", EXPORTS)
    sha = read_pe_exports(dll).sha256
    hand_dir = tmp_path / "d"
    hand_dir.mkdir()
    other = hand_dir / "other_f.json"
    other.write_text(json.dumps({
        "format_version": 1, "kind": "declared", "id": "other-f", "version": 1, "language_id": WIN64[0],
        "abi_tag": WIN64[1], "libraries": ["OTHER2.DLL"], "stack_pointer": [32, 8], "stack_delta": 8,
        "preserved": [[24, 8]], "entries": [{"name": "F", "original_names": [MANGLED], "registers": [],
                                             "memory": [],
                                             **NO_CALLBACKS, "other_memory": "preserved"}]}), encoding="utf-8")
    # derived with OTHER2.DLL's F loaded (a recorded model of the same name)
    models = load_external_models([_hand_file(hand_dir), other], *WIN64)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
    units = program_units(_caller_writes(THUNK))
    linker = Linker([LinkTarget(LIBRARY, dll)], tmp_path / "cache", FakeProvider(sha), FakeDeriver(sha),
                    log=lambda line: None)
    linked, _ = linker(units, info, external_models=models, pcodeop_models=None, private_frame_above=0,
                       traps=True, globals_disjoint=True, direction_flag=True)
    assert _rows(linker.report) == {MANGLED: ("derived", None)}
    derived = analyze_units(units, image_info=info, external_models=linked, assume_direction_flag_clear=True,
                            assume_debug_break_traps_do_not_return=True,
                            assume_globals_disjoint_from_stack=True)["1:1000"]
    inside = analyze_units(program_units(_caller_writes(F), BODY), assume_direction_flag_clear=True,
                           assume_debug_break_traps_do_not_return=True,
                           assume_globals_disjoint_from_stack=True)["1:1000"]
    a, b = _effect(inside), _effect(derived)
    assert (a.preserves_memory, a.restores_stack, a.preserved, a.observes_registers) == \
        (b.preserves_memory, b.restores_stack, b.preserved, b.observes_registers)
    assert _views(inside, POINTS) == _views(derived, POINTS)
    assert any(label.startswith("derived-model:link-synth-dll-") for label in derived.declared.values())


def test_a_plain_model_matching_a_recorded_name_without_its_underscore_blocks_the_template(tmp_path):
    """Lookup matches a plain (unqualified) model by name with leading
    underscores stripped; the template check compares the same way."""
    from tdo_v2.summary_store import with_model_files
    from tdo_v2.summary_templates import refusal

    dll = _pe(tmp_path / "synth.dll", EXPORTS)
    sha = read_pe_exports(dll).sha256
    hand_dir = tmp_path / "d"
    hand_dir.mkdir()
    qualified = hand_dir / "x_foo.json"
    qualified.write_text(json.dumps({
        "format_version": 1, "kind": "declared", "id": "x-foo", "version": 1, "language_id": WIN64[0],
        "abi_tag": WIN64[1], "libraries": ["X.DLL"], "stack_pointer": [32, 8], "stack_delta": 8,
        "preserved": [[24, 8]], "entries": [{"name": "_foo", "original_names": ["_foo"], "registers": [],
                                             "memory": [],
                                             **NO_CALLBACKS, "other_memory": "preserved"}]}), encoding="utf-8")
    plain = tmp_path / "plain_foo.json"
    plain.write_text(json.dumps({
        "format_version": 1, "kind": "declared", "id": "plain-foo", "version": 1, "language_id": WIN64[0],
        "abi_tag": WIN64[1], "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8]],
        "entries": [{"name": "foo", "registers": [], "memory": [], **NO_CALLBACKS, "other_memory": "preserved"}]}),
        encoding="utf-8")
    models = load_external_models([_hand_file(hand_dir), qualified], *WIN64)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
    units = program_units(_caller_writes(THUNK))
    linker = Linker([LinkTarget(LIBRARY, dll)], tmp_path / "cache", FakeProvider(sha), FakeDeriver(sha),
                    log=lambda line: None)
    linked, _ = linker(units, info, external_models=models, pcodeop_models=None, private_frame_above=0,
                       traps=True, globals_disjoint=True, direction_flag=True)
    template_file = next(item for item in linked.files if item.file_id.startswith("link-"))
    namespace = units[0].scopes.program.evidence.translation_namespace
    language = (namespace.language_id, namespace.major_version, namespace.minor_version)
    assert refusal(template_file, template_file.entries[0], external_models=linked, pcodeop_models=None,
                   private_frame_above=0, language=language) is None
    reason = refusal(template_file, template_file.entries[0], external_models=with_model_files(linked, [plain]),
                     pcodeop_models=None, private_frame_above=0, language=language)
    assert reason is not None and "plain-foo" in reason
