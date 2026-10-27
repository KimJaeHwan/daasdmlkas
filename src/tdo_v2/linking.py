"""Linking a program with the real code of a library it imports (design section 24).

``run_dfbench --link LIB=DLL --ghidra-project X.gpr`` hands each linked
library to ``Linker``; the summary engine calls it once, after the program's
functions are read and before they are analyzed (``analyze_frozen_bundle_with_
summaries(linker=...)``). For each linked library it

1. checks coverage: the DLL file exports every function the program imports
   from that library (else it is not the library the program was built
   against: an error);
2. takes the imports the program calls (``interprocedural.import_call_sites``);
   an import some loaded model already covers keeps that model (hand model
   first: such an import is never derived);
3. looks each remaining exported function up in the cache
   ``<cache>/<LIB>/<dll sha256>/<profile>/`` (the profile digest names
   everything a template depends on besides the DLL: engine versions, the
   analysis settings of this run, the p-code op and hand model files, the
   provider -- Ghidra and exporter -- identity);
4. derives the misses from the library's real code: the provider exports their
   call closure from the user's prepared Ghidra project (cut at the library's
   internal hand models) and scans the library once for stack switches; the
   templates are derived with the declared (hand) models only
   (``derive_models.derive_library``) and stored one file per export;
5. applies one template per import (the program's model set gains the
   template files; each use is checked by ``summary_templates.refusal`` and
   reported like any derived model), and adds the library's stack evidence to
   the run's (a switch in the library withdraws globals-disjoint-from-stack).

Refusals are classed: ``semantic`` (the analysis cannot express the
function: stored, not retried with the same profile), ``budget`` and
``infrastructure`` (Ghidra / export / Bundle failures: never stored, retried
next run). v1 links exported functions only: a data export or a forwarder is
reported, not derived. Every import gets one report row (``LinkRow``).

The tools never import or analyze a library in Ghidra: the user prepares the
project (tools/bundle_export/README.md).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

LINK_FORMAT = 1
SEMANTIC, BUDGET, INFRASTRUCTURE = "semantic", "budget", "infrastructure"
_ORDINAL = re.compile(r"Ordinal_(\d+)")
_MACHINES = {0x8664: "x86:LE:64", 0x14C: "x86:LE:32"}   # PE machine -> the Ghidra language it runs with


class LinkError(ValueError):
    """The link itself is wrong (another DLL, nothing imported from it)."""


class ProviderError(RuntimeError):
    """A provider step failed; ``refusal_class``: budget or infrastructure."""

    def __init__(self, message: str, refusal_class: str = INFRASTRUCTURE):
        super().__init__(message)
        self.refusal_class = refusal_class


@dataclass(frozen=True, slots=True)
class LinkTarget:
    library: str      # the import library name, e.g. LIBFOO.DLL
    dll: Path

    @staticmethod
    def parse(text: str) -> "LinkTarget":
        library, sep, path = text.partition("=")
        if not sep or not library or not path:
            raise LinkError(f"--link takes LIBRARY=PATH, not {text!r}")
        return LinkTarget(library.upper(), Path(path))


@dataclass(frozen=True, slots=True)
class LinkRow:
    library: str
    name: str          # the import's original (mangled) name
    status: str        # model | cached | derived | unusable | refused | data | forwarder | ordinal | pending
    detail: str = ""
    refusal_class: str | None = None
    file_id: str | None = None   # the template's model file (cached / derived)

    def describe(self) -> str:
        detail = f" ({self.refusal_class}: {self.detail})" if self.refusal_class else \
            (f" ({self.detail})" if self.detail else "")
        return f"{self.library}!{self.name}: {self.status}{detail}"


@dataclass(slots=True)
class LinkReport:
    rows: list = field(default_factory=list)
    lines: list = field(default_factory=list)   # per-library notes (coverage, cache, evidence)
    template_files: list = field(default_factory=list)
    evidence_files: list = field(default_factory=list)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _name_key(name: str) -> str:
    return _sha256(name.encode("utf-8"))[:20]


def _write_json(path: Path, raw) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(raw, indent=1) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _export_of(exports, name: str):
    """The PE export an import names (by name, or ``Ordinal_N``), or None."""
    found = exports.by_name().get(name)
    if found is None:
        match = _ORDINAL.fullmatch(name)
        found = exports.by_ordinal().get(int(match.group(1))) if match else None
    return found


def declared_models(models):
    """The hand (declared) model files of ``models``: what templates are derived with."""
    from .summary_store import ExternalModels

    return ExternalModels(tuple(item for item in models.files
                                if all(entry.template is None for entry in item.entries)))


def _disabled(switches: dict) -> set:
    """The assumptions a link run with ``switches`` has switched off (read-only
    image folding is off in every derivation)."""
    from .assumptions import disabled

    return disabled(
        globals_disjoint=switches["globals_disjoint"], readonly_image=False,
        direction_flag=switches["direction_flag"], entry_values_not_frame=switches["entry_values_not_frame"],
        home_space=bool(switches["private_frame_above"]), opaque_no_stack=switches["opaque_no_stack"],
        traps=switches["traps"], import_slots=switches["import_slots"], same_result=switches["same_result"],
        accessor_separate=switches["accessor_separate"], accessor_private_state=switches["accessor_private_state"],
        registered_handlers=switches["registered_handlers"], model_assumptions_off=switches["model_assumptions_off"])


def profile(*, switches: dict, pcodeop_models, models, language_id: str, abi_tag: str,
            provider_identity: dict, evidence: str | None, catalog_models=()) -> dict:
    """Everything a linked template depends on besides the DLL itself:
    ``switches``, the run's analysis settings the derivation takes
    (``Linker.__call__``); ``evidence``, the sha256 of the library's stack
    evidence file (None: none -- a later clean scan derives again);
    ``catalog_models``: the declaration-only model files (what each
    declaration states)."""
    from .function_summary import FUNCTION_SUMMARY_VERSION
    from .interprocedural import MAX_RECURSION_ROUNDS
    from .summary_templates import ENGINE_SEMANTICS_VERSION, TEMPLATE_VERSION, pcodeop_digest

    return {
        "link_format": LINK_FORMAT,
        "engine": {"summary_version": FUNCTION_SUMMARY_VERSION, "template_version": TEMPLATE_VERSION,
                   "semantics_version": ENGINE_SEMANTICS_VERSION, "recursion_rounds": MAX_RECURSION_ROUNDS},
        "language_id": language_id, "abi_tag": abi_tag,
        "switches": dict(sorted(switches.items())),
        "pcodeops": pcodeop_digest(pcodeop_models),
        "models": sorted([item.file_id, item.digest] for item in declared_models(models).files),
        "provider": provider_identity,
        "stack_evidence": evidence,
        "declarations": sorted([label, statement, fails_when] for models in catalog_models
                               for item in models.files for label, statement, fails_when in item.declares),
    }


def profile_digest(raw: dict) -> str:
    return _sha256(json.dumps(raw, sort_keys=True).encode("utf-8"))[:16]


class LinkCache:
    """``<root>/<LIB>/<dll sha256>/<profile digest>/``: ``templates/<name key>.json``
    (a one-entry summary file), ``refusals/<name key>.json`` (the derivation's
    own refusals, with their class -- the same Bundle and profile give the
    same result: retried with --link-refresh or another profile),
    ``profile.json``. Stack evidence: ``<root>/<LIB>/<dll sha256>/stack-<scanner>.json``."""

    def __init__(self, root: Path, library: str, dll_sha256: str, profile_raw: dict):
        self.library_dir = Path(root) / library / dll_sha256
        self.directory = self.library_dir / profile_digest(profile_raw)
        self.profile = profile_raw

    def template(self, name: str) -> Path:
        return self.directory / "templates" / f"{_name_key(name)}.json"

    def refusal(self, name: str) -> Path:
        return self.directory / "refusals" / f"{_name_key(name)}.json"

    def lookup(self, name: str):
        """("template", path, file id) | ("refused", reason, class) | None (an
        unreadable file counts as a miss: derived again and overwritten)."""
        from .summary_store import ModelError, load_model_file

        path = self.template(name)
        digest = path.with_suffix(".sha256")
        if path.is_file():
            try:
                if not digest.is_file() or digest.read_text(encoding="ascii").strip() != \
                        _sha256(path.read_bytes()):
                    raise ValueError("not the file stored")
                loaded = load_model_file(path)
                if [entry.name for entry in loaded.entries] == [name]:
                    return "template", path, loaded.file_id
            except (OSError, ValueError, KeyError, TypeError, ModelError):
                pass
        path = self.refusal(name)
        if path.is_file():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if raw.get("name") == name and raw.get("class") in (SEMANTIC, BUDGET, INFRASTRUCTURE) \
                        and type(raw.get("reason")) is str:
                    return "refused", raw["reason"], raw["class"]
            except (OSError, ValueError, AttributeError):
                pass
        return None

    def store_template(self, name: str, raw: dict) -> Path:
        """The latest derivation replaces whatever was stored for ``name``."""
        self._profile_file()
        path = self.template(name)
        _write_json(path, raw)
        digest = path.with_suffix(".sha256")
        temporary = digest.with_name(digest.name + f".{os.getpid()}.tmp")
        temporary.write_text(_sha256(path.read_bytes()) + "\n", encoding="ascii")
        os.replace(temporary, digest)
        self.refusal(name).unlink(missing_ok=True)
        return path

    def store_refusal(self, name: str, reason: str, refusal_class: str = SEMANTIC) -> None:
        self._profile_file()
        _write_json(self.refusal(name), {"name": name, "class": refusal_class, "reason": reason})
        self.template(name).unlink(missing_ok=True)
        self.template(name).with_suffix(".sha256").unlink(missing_ok=True)

    def forget(self, name: str) -> None:
        """A non-semantic failure (--link-refresh): nothing stays stored for ``name``."""
        self.refusal(name).unlink(missing_ok=True)
        self.template(name).unlink(missing_ok=True)
        self.template(name).with_suffix(".sha256").unlink(missing_ok=True)

    def _profile_file(self) -> None:
        path = self.directory / "profile.json"
        if not path.is_file():
            _write_json(path, self.profile)


def split_templates(raw: dict, library: str, dll_sha256: str) -> dict:
    """{export name: a one-entry summary file} of a derived file; each file
    id is unique to the library build and the name."""
    files = {}
    for entry in raw["entries"]:
        single = {key: value for key, value in raw.items() if key != "entries"}
        single["id"] = f"link-{re.sub('[^a-z0-9]+', '-', library.lower()).strip('-')}-{dll_sha256[:12]}-" \
                       f"{_name_key(entry['name'])}"
        single["entries"] = [entry]
        files[entry["name"]] = single
    return files


class Linker:
    """The engine's linking hook (see the module docstring). ``provider``:
    ``identity() -> dict``, ``stack_evidence(target, cache_path) -> Path``,
    ``export(target, entries, space_id) -> Bundle generation path`` where
    entries are (name, address); ``deriver``: ``derive_models.derive_library``
    (or a test double) with the same keywords."""

    def __init__(self, targets, cache_root: Path, provider, deriver, *, refresh: bool = False,
                 dry_run: bool = False, log=print):
        self.targets = list(targets)
        self.cache_root = Path(cache_root)
        self.provider = provider
        self.deriver = deriver
        self.refresh = refresh
        self.dry_run = dry_run   # report the misses ("pending"), derive nothing
        self.log = log
        self.report = LinkReport()

    def __call__(self, units, image_info, *, external_models, pcodeop_models, private_frame_above: int,
                 traps: bool, globals_disjoint: bool, direction_flag: bool, import_slots: bool = False,
                 entry_values_not_frame: bool = True, same_result: bool = False,
                 accessor_separate: bool = False, opaque_no_stack: bool = True, registered_handlers: bool = True,
                 accessor_private_state: bool = False, model_assumptions_off=(), catalog_models=()):
        """(the run's model set with the linked templates, stack evidence
        files). The settings are the run's effective ones (``globals_disjoint``
        after the program's own withdrawal checks): templates are derived with
        exactly these, so none rests on an assumption the run switched off.
        ``catalog_models``: the run's binding model files (their declarations
        resolve labels, ``summary_store.assumption_catalog``)."""
        from .interprocedural import import_call_sites
        from .pe_exports import read_pe_exports
        from .summary_store import ExternalModels, with_model_files

        if image_info is None:
            raise LinkError("linking needs the Bundle's image facts (image_info)")
        models = external_models if external_models is not None else ExternalModels(())
        languages = {(item.language_id, item.abi_tag) for item in models.files}
        if len(languages) != 1:
            raise LinkError("linking needs the run's hand models of one language and ABI")
        language_id, abi_tag = languages.pop()
        called = {}
        for unit in units:
            for symbol in import_call_sites(unit, image_info).values():
                called.setdefault((symbol.library.upper(), symbol.original_name or symbol.name), symbol)
        from .relative_memory import index_addresses

        space_id = units[0].scopes.program.evidence.image_base.space_id
        # the home-space extension is inactive without its base assumption
        switches = {"private_frame_above": private_frame_above if entry_values_not_frame else 0, "traps": bool(traps),
                    "globals_disjoint": bool(globals_disjoint), "direction_flag": bool(direction_flag),
                    "import_slots": bool(import_slots), "index_addresses": index_addresses(),
                    "entry_values_not_frame": bool(entry_values_not_frame), "same_result": bool(same_result),
                    "accessor_separate": bool(accessor_separate), "opaque_no_stack": bool(opaque_no_stack),
                    "registered_handlers": bool(registered_handlers),
                    "accessor_private_state": bool(accessor_private_state),
                    "model_assumptions_off": sorted(set(model_assumptions_off))}
        identity = self.provider.identity()
        declared = declared_models(models)
        checked = []
        for target in self.targets:   # every check before anything is scanned or derived
            exports = read_pe_exports(target.dll)
            machine = _MACHINES.get(exports.machine)
            if machine is None or not language_id.startswith(machine):
                raise LinkError(f"{target.dll}: PE machine {exports.machine:#x} does not run with {language_id}")
            imported = [row for row in image_info.imports if row.library.upper() == target.library]
            if not imported:
                raise LinkError(f"the program imports nothing from {target.library}")
            absent = sorted({row.original_name or row.name for row in imported
                             if _export_of(exports, row.original_name or row.name) is None})
            if absent:
                raise LinkError(f"{target.dll} does not export {len(absent)} of the program's imports from "
                                f"{target.library} (e.g. {absent[0]}): not the library the program was built against")
            checked.append((target, exports, imported))
        from .stack_evidence import load_stack_evidence

        if self.refresh and not self.dry_run:
            import shutil

            for target, exports, _ in checked:
                # the library may have been re-analyzed: nothing derived from
                # the old analysis may stay, under any profile
                shutil.rmtree(self.cache_root / target.library / exports.sha256, ignore_errors=True)
        evidences = {}
        for target, exports, _ in checked:
            # the library's code runs in this program whenever it is linked:
            # its evidence joins the run's (scanned once per build; a dry run
            # only uses a scan already made)
            evidence = self._evidence(target, exports.sha256)
            evidences[target] = evidence
            if evidence is not None:
                self.report.evidence_files.append(evidence)
                if not load_stack_evidence(evidence).clean:
                    # the run will withdraw the assumption: no template may rest on it
                    switches["globals_disjoint"] = False
        # import-slots-hold-their-exports only acts with globals-disjoint-from-stack:
        # the profile and the derivation state what is actually used
        switches["import_slots"] = switches["import_slots"] and switches["globals_disjoint"]
        for target, exports, imported in checked:
            evidence = evidences[target]
            profile_raw = profile(switches=switches, pcodeop_models=pcodeop_models, models=models,
                                  catalog_models=catalog_models,
                                  language_id=language_id, abi_tag=abi_tag, provider_identity=identity,
                                  evidence=_sha256(evidence.read_bytes()) if evidence is not None else None)
            cache = LinkCache(self.cache_root, target.library, exports.sha256, profile_raw)
            needed = sorted(name for library, name in called if library == target.library)
            self.report.lines.append(
                f"{target.library} = {target.dll} (sha256 {exports.sha256[:12]}): {len(imported)} imports, all "
                f"exported; {len(needed)} called; cache {cache.directory}")
            misses = []
            for name in needed:
                symbol = called[(target.library, name)]
                export = _export_of(exports, name)
                found = models.lookup(symbol)
                off = set(found[1].inherited) & _disabled(switches) if found is not None else set()
                if found is not None and (found[1].refusal is not None or off):
                    # (not replaced by a derived template: two models of one
                    # import conflict; the call stays opaque, as the hand
                    # model's application would be refused)
                    why = found[1].refusal or f"rests on {', '.join(sorted(off))}, switched off in this run"
                    self._row(target, name, "model-unusable", f"{found[1].label}: {why}")
                elif found is not None:
                    self._row(target, name, "model", found[1].label)
                elif export.kind == "data":
                    self._row(target, name, "data", "a data export: nothing to derive")
                elif export.kind == "forwarder":
                    self._row(target, name, "forwarder", f"forwarded to {export.forward} (not followed in v1)")
                elif export.name is None or export.name != name:
                    self._row(target, name, "ordinal", "imported by ordinal (not linked in v1)")
                elif self.dry_run and evidence is None:
                    self._row(target, name, "pending", "no stack evidence yet: the cache was not consulted")
                else:
                    hit = None if self.refresh else cache.lookup(name)
                    if hit is None:
                        misses.append(export)
                    elif hit[0] == "template":
                        self.report.template_files.append(hit[1])
                        self._row(target, name, "cached", file_id=hit[2])
                    else:
                        self._row(target, name, "refused", hit[1], hit[2])
            if self.dry_run:
                for export in misses:
                    self._row(target, export.name, "pending", "would be derived")
                misses = []
            if misses:
                self._derive(target, exports, cache, misses, space_id, declared, evidence, switches,
                             pcodeop_models, catalog_models)
        linked = with_model_files(models, self.report.template_files)
        namespace = units[0].scopes.program.evidence.translation_namespace
        disabled = _disabled(switches)
        if self._preflight(linked, pcodeop_models=pcodeop_models, private_frame_above=switches["private_frame_above"],
                           language=(namespace.language_id, namespace.major_version, namespace.minor_version),
                           disabled=disabled, catalog_models=catalog_models):
            linked = with_model_files(models, self.report.template_files)
        for row in self.report.rows:
            self.log(f"[link] {row.describe()}")
        return linked, tuple(self.report.evidence_files)

    def _row(self, target, name, status, detail="", refusal_class=None, file_id=None):
        self.report.rows.append(LinkRow(target.library, name, status, detail, refusal_class, file_id))

    def _evidence_path(self, library: str, dll_sha256: str) -> Path:
        """Keyed by the scanner's whole identity (Ghidra version and sources)."""
        identity = _sha256(json.dumps(self.provider.identity(), sort_keys=True).encode("utf-8"))[:16]
        return self.cache_root / library / dll_sha256 / f"stack-{identity}.json"

    def _evidence(self, target, dll_sha256: str):
        """The library's whole-program stack evidence (scanned once per DLL build)."""
        from .stack_evidence import EvidenceError, load_stack_evidence

        path = self._evidence_path(target.library, dll_sha256)
        if path.is_file() and self.refresh and not self.dry_run:
            path.unlink()   # --link-refresh: the library may have been re-analyzed: scan again
        if path.is_file():
            try:
                if load_stack_evidence(path).executable_sha256 == dll_sha256:
                    return path
            except (EvidenceError, OSError, ValueError):
                pass
            if not self.dry_run:
                path.unlink()
        if self.dry_run:
            self.report.lines.append(f"{target.library}: no stack evidence yet (a real run scans the library once)")
            return None
        try:
            self.provider.stack_evidence(target, path)
            if load_stack_evidence(path).executable_sha256 != dll_sha256:
                raise EvidenceError(f"{path}: the scan is of another binary")
        except (ProviderError, EvidenceError, OSError, ValueError) as error:
            if path.is_file():
                path.unlink()
            self.report.lines.append(f"{target.library}: NO stack evidence ({error}); its templates are derived "
                                     "without globals-disjoint-from-stack, and it cannot withdraw the assumption "
                                     "for the run")
            return None
        return path

    def _derive(self, target, exports, cache, misses, space_id, declared, evidence, switches, pcodeop_models,
                catalog_models=()):
        names = [export.name for export in misses]
        entries = [(export.name, exports.image_base + export.rva) for export in misses]
        self.log(f"[link] {target.library}: deriving {len(names)} exports from the prepared Ghidra project")
        try:
            # one Ghidra export for all (one launch); each export then
            # analyzed alone, so no template depends on the others
            generation = self.provider.export(target, entries, space_id)
            files, refused, missing = self.deriver(
                generation, target.library, names, file_id=f"link-{target.library.lower()}",
                models=declared, pcodeops=pcodeop_models, stack_evidence=[evidence] if evidence is not None else [],
                private_frame_above=switches["private_frame_above"], traps=switches["traps"],
                assume_globals_disjoint=switches["globals_disjoint"], direction_flag=switches["direction_flag"],
                import_slots=switches["import_slots"], entry_values_not_frame=switches["entry_values_not_frame"],
                same_result=switches["same_result"], accessor_separate=switches["accessor_separate"],
                opaque_no_stack=switches["opaque_no_stack"], registered_handlers=switches["registered_handlers"],
                accessor_private_state=switches["accessor_private_state"],
                model_assumptions_off=tuple(switches["model_assumptions_off"]), catalog_models=catalog_models,
                per_export=True, log=lambda line: self.log(f"[link]   {line}"))
            for raw in files.values():
                if raw["source"]["sha256"] != exports.sha256:
                    raise ProviderError(f"the exported Bundle is of {raw['source']['sha256'][:12]}, "
                                        f"not of {target.dll}")
        except ProviderError as error:
            for name in names:
                self._failed(cache, target, name, str(error), error.refusal_class)
            return
        except Exception as error:  # noqa: BLE001 -- a failed derivation run: retried next time
            for name in names:
                self._failed(cache, target, name, f"{type(error).__name__}: {error}", INFRASTRUCTURE)
            return
        for name in names:
            if name in files:
                single = split_templates(files[name], target.library, exports.sha256)[name]
                self.report.template_files.append(cache.store_template(name, single))
                self._row(target, name, "derived", file_id=single["id"])
            elif name in refused and getattr(refused[name], "kind", None) == "transient":
                self._failed(cache, target, name, str(refused[name]), INFRASTRUCTURE)
            elif name in refused:
                # the derivation's own verdict on this export: stored with its class
                refusal_class = refusal_class_of(refused[name])
                cache.store_refusal(name, str(refused[name]), refusal_class)
                self._row(target, name, "refused", str(refused[name]), refusal_class)
            elif name in missing:
                cache.store_refusal(name, "not in the exported Bundle", INFRASTRUCTURE)
                self._row(target, name, "refused", "not in the exported Bundle", INFRASTRUCTURE)
            else:
                self._failed(cache, target, name, "no template produced", INFRASTRUCTURE)

    def _failed(self, cache, target, name, reason, refusal_class):
        """A failed derivation run (Ghidra, export, a crash): reported, nothing
        stored (and, under --link-refresh, nothing older kept), retried next run."""
        cache.forget(name)
        self._row(target, name, "refused", reason, refusal_class)

    def _preflight(self, linked, *, pcodeop_models, private_frame_above, language, disabled, catalog_models=()):
        """Each linked template checked as the engine will check it at a call
        (``summary_templates.refusal`` against the final model set, and the
        assumptions this run switched off): an unusable one is reported and
        left out, never claimed as linked."""
        from .summary_store import assumption_catalog, with_model_files
        from .summary_templates import refusal

        catalog = assumption_catalog(linked, *catalog_models)
        by_id = {item.file_id: item for item in linked.files}
        usable_files, changed = [], False
        for path in self.report.template_files:
            usable_files.append(path)
        for index, row in enumerate(self.report.rows):
            if row.status not in ("derived", "cached") or row.file_id not in by_id:
                continue
            model_file = by_id[row.file_id]
            (entry,) = model_file.entries
            reason = refusal(model_file, entry, external_models=linked, pcodeop_models=pcodeop_models,
                             private_frame_above=private_frame_above, language=language, catalog=catalog)
            off = sorted(set(entry.inherited) & disabled)
            if reason is None and off:
                reason = f"rests on {', '.join(off)}, switched off in this run"
            if reason is not None:
                self.report.rows[index] = LinkRow(row.library, row.name, "unusable", f"{row.status}, but {reason}",
                                                  None, row.file_id)
                usable_files = [path for path in usable_files if _file_id(path) != row.file_id]
                changed = True
        if changed:
            self.report.template_files = usable_files
        return changed


def refusal_class_of(reason) -> str:
    """A derivation refusal's class: its ``kind`` (``summary_templates.Refusal``:
    not analyzed -> infrastructure, a recursion without a verified fixpoint
    in the round budget -> budget), else semantic."""
    kind = getattr(reason, "kind", SEMANTIC)
    return kind if kind in (SEMANTIC, BUDGET, INFRASTRUCTURE) else SEMANTIC


def _file_id(path) -> str:
    return json.loads(Path(path).read_text(encoding="utf-8"))["id"]


__all__ = ("BUDGET", "INFRASTRUCTURE", "LINK_FORMAT", "LinkCache", "LinkError", "LinkReport", "LinkRow",
           "LinkTarget", "Linker", "ProviderError", "SEMANTIC", "declared_models", "profile", "profile_digest",
           "refusal_class_of", "split_templates")
