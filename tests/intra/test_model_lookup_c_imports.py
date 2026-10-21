"""A model file naming its library matches an import by (library, the name as
imported): a C export has no separate original name (``original_name`` is
None) and is imported under its name -- linked templates of C DLLs (docs
25.13, the 09 testbed's libdfbench_importlib.dll) were never applied."""

import json
from pathlib import Path

from synthetic import NO_CALLBACKS
from tdo_v2.image_info import ImportedSymbol
from tdo_v2.summary_store import load_external_models

WIN64 = ("x86:LE:64:default", "win64")


def _library_file(directory, library, original_names):
    raw = {"format_version": 1, "kind": "declared", "id": "lib-hand", "version": 1,
           "language_id": WIN64[0], "abi_tag": WIN64[1], "libraries": [library],
           "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
           "entries": [{"name": "f", "original_names": list(original_names), "registers": [], "memory": [],
                        **NO_CALLBACKS, "other_memory": "preserved"}]}
    path = Path(directory) / "lib.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return load_external_models([path], *WIN64)


def test_a_c_import_without_an_original_name_matches_by_its_name(tmp_path):
    models = _library_file(tmp_path, "LIB.DLL", ["dfb_import_identity"])
    found = models.lookup(ImportedSymbol("LIB.DLL", "dfb_import_identity", None, (), ()))
    assert found is not None and found[1].names == ("f",)
    assert models.lookup(ImportedSymbol("lib.dll", "dfb_import_identity", None, (), ())) is not None


def test_the_library_and_the_original_name_still_decide(tmp_path):
    models = _library_file(tmp_path, "LIB.DLL", ["?F@@YAXXZ"])
    assert models.lookup(ImportedSymbol("OTHER.DLL", "F", "?F@@YAXXZ", (), ())) is None
    assert models.lookup(ImportedSymbol("LIB.DLL", "F", "?G@@YAXXZ", (), ())) is None
    assert models.lookup(ImportedSymbol("LIB.DLL", "?F@@YAXXZ", None, (), ())) is not None
    assert models.lookup(ImportedSymbol("LIB.DLL", "F", "?F@@YAXXZ", (), ())) is not None
