"""Code-only profile: a run whose call effects come from analyzed code only.

The engine's founding rule is "no ret / no arg / no convention": no calling
convention or ABI fact (which registers a call keeps, where arguments live,
who owns the stack slots above a frame) is assumed. Several named
assumptions (``assumptions.REGISTRY``) are such facts, or behavior claims
of the same kind, and are on by default; hand-written models state
effects nobody derived. A run under this profile:

* forces one exact assumption switch vector (``switch_vector``) over the
  whole run -- the analysis of the program itself, every template it
  consumes, and every template derived for it -- whatever the caller,
  the environment or the command line asked for: only the environmental /
  translator facts in ``ON`` stay on;
* uses no hand model of any kind (declared, supplied, bound, library
  internal cuts, lifecycle contracts): only derived templates
  (``summary_templates``) of the libraries the build manifest pins, by the
  full SHA-256 of the file analyzed -- a template of any other file is not
  applicable (as if absent);
* admits a template only when it was derived under the same vector
  (``source.code_only_switches``) and every label it rests on, transitively,
  is in ``ALLOWED_LABELS`` / ``ALLOWED_PREFIXES`` (an allowlist: a new
  label is refused until someone decides it is not a convention).

The manifest's ``language_id`` / ``abi_tag`` are compatibility labels for
the model file format only; they license no ABI semantics. Library names
are data (the manifest), never engine code.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .assumptions import switches

MANIFEST_FORMAT = "tdo-code-only-build/1"

# registry switches that stay ON: facts about the loaded image / the
# translator, not about how code is written (``external-models`` is the
# mechanism that loads templates; ``admit`` keeps only derived ones)
ON = frozenset({"readonly-image-data-is-constant", "import-slots-hold-their-exports", "external-models"})
# registry ``model`` assumptions switched off: hand-model contracts
MODEL_OFF = ("allocator-results-are-fresh", "no-use-after-free", "no-use-of-old-pointer-after-realloc",
             "library-internal-model-cuts")
# labels a consumed template may rest on (transitively)
ALLOWED_LABELS = frozenset({"derived-model-runtime-matches", "import-slots-hold-their-exports",
                            "readonly-image-data-is-constant", "lock-markers-have-no-data-effect"})
ALLOWED_PREFIXES = ("derived-model:", "pcodeop-model:")


class ProfileError(ValueError):
    """An input the code-only profile does not take (a hand model, a binding...)."""


def switch_vector() -> dict[str, bool]:
    """Registry switch name -> forced value (every ``switch`` row)."""
    return {row.name: row.name in ON for row in switches()}


def forced_arguments() -> dict[str, bool]:
    """``analyze_frozen_bundle_with_summaries`` keyword -> forced value (the
    switch rows but ``external-models``, whose keyword is the model set)."""
    return {row.parameter: row.name in ON for row in switches() if row.name != "external-models"}


def required_off() -> set[str]:
    """Every registry label the profile switches off (switch rows not in
    ``ON``, and ``MODEL_OFF``)."""
    return {name for name, on in switch_vector().items() if not on} | set(MODEL_OFF)


# ``interprocedural._analyze_units`` boolean keywords of switches the profile
# turns off (the others: ``analyze_units``' own keywords, ``private_frame_above``)
_ANALYSIS_OFF = ("assume_globals_disjoint_from_stack", "assume_direction_flag_clear",
                 "assume_debug_break_traps_do_not_return", "assume_same_result_functions",
                 "assume_accessor_result_separate", "assume_accessor_private_state",
                 "assume_registered_handlers_not_observed", "assume_faults_end_execution",
                 "assume_stock_ghidra_translator")


def label_allowed(label: str) -> bool:
    return label in ALLOWED_LABELS or label.startswith(ALLOWED_PREFIXES)


@dataclass(frozen=True)
class CodeOnlyProfile:
    language_id: str
    abi_tag: str                            # a model-file compatibility label only
    libraries: tuple[tuple[str, str], ...]  # (upper-case file name, sha256 hex) pinned
    digest: str = ""                        # of the manifest (reports, caches)

    def library_sha(self, name: str) -> str | None:
        return dict(self.libraries).get(name.upper())

    def check_inputs(self, *, model_bindings=(), lifecycle_contracts=(), linker=None,
                     boundary_call_effects=False) -> None:
        """Inputs no code-only run takes: a refusal, never a silent drop."""
        if tuple(model_bindings):
            raise ProfileError("code-only profile: model bindings are hand models")
        if tuple(lifecycle_contracts or ()):
            raise ProfileError("code-only profile: lifecycle contracts are hand models")
        if linker is not None:
            raise ProfileError("code-only profile: on-demand linking is not wired to the profile yet")
        if boundary_call_effects:
            raise ProfileError("code-only profile: test-only boundary effects")

    def analysis_options(self, options: dict) -> dict:
        """``interprocedural._analyze_units`` keywords under the profile."""
        for key in ("model_bindings", "lifecycle_contracts", "assumption_declarations"):
            if tuple(options.get(key) or ()):
                raise ProfileError(f"code-only profile: {key} are hand models")
        if options.get("declared_boundaries") or options.get("assumed_call_effects"):
            raise ProfileError("code-only profile: test-only boundary effects")
        forced = dict(options)
        forced.update({key: False for key in _ANALYSIS_OFF})
        forced["private_frame_above"] = 0   # (win64-home-space-callee-private off)
        forced["disabled_model_assumptions"] = tuple(sorted(
            set(options.get("disabled_model_assumptions") or ()) | set(MODEL_OFF)))
        forced["external_models"] = self.admit(options.get("external_models"))
        forced["code_only_profile"] = self
        return forced

    def check_disabled(self, disabled) -> None:
        """The run's effective switched-off labels include every one the
        profile turns off (a coupling or a new switch cannot re-enable one)."""
        missing = required_off() - set(disabled)
        if missing:
            raise ProfileError("code-only profile: still on in this run: " + ", ".join(sorted(missing)))

    def admit(self, external_models):
        """``external_models`` with only the templates of pinned files: a
        hand-model file is an error; a template of another file (another
        library, another build of it) is not applicable and left out."""
        from .summary_store import ExternalModels

        if external_models is None:
            return ExternalModels(())
        kept = []
        for model_file in external_models.files:
            if any(entry.template is None for entry in model_file.entries):
                raise ProfileError(f"code-only profile: {model_file.file_id} is a hand model file")
            if model_file.language_id != self.language_id:
                continue
            sha = model_file.source_field("sha256")
            if len(model_file.libraries) == 1 and sha is not None \
                    and self.library_sha(model_file.libraries[0]) == sha:
                kept.append(model_file)
        return ExternalModels(tuple(kept))

    def load_models(self, model_dirs=()):
        """The admitted templates of the ``*.json`` files in ``model_dirs``
        (never the repository's hand models; ``TDO_V2_MODEL_DIRS`` is
        refused: a run's model set is its command line)."""
        import os

        from .summary_store import ModelError, load_model_file, validated_models

        if os.environ.get("TDO_V2_MODEL_DIRS"):
            raise ProfileError("code-only profile: TDO_V2_MODEL_DIRS is set (pass --model-dir)")
        files, seen = [], set()
        for directory in map(Path, model_dirs):
            if not directory.is_dir():
                raise ModelError(f"model directory not found: {directory}")
            for path in sorted(directory.glob("*.json")):
                if path.resolve() not in seen:
                    seen.add(path.resolve())
                    files.append(load_model_file(path))
        return self.admit(validated_models(item for item in files if item.language_id == self.language_id))

    def refusal(self, model_file, entry) -> str | None:
        """Why ``entry`` is not applied under the profile (every selection
        route checks it), or None."""
        if entry.template is None:
            return "code-only profile: a hand model"
        if len(model_file.libraries) != 1 \
                or self.library_sha(model_file.libraries[0]) != model_file.source_field("sha256"):
            return "code-only profile: a template of a file the build does not pin"
        if model_file.source_field("code_only_switches") != switch_vector():
            return "code-only profile: derived under another assumption vector"
        outside = sorted(label for label in entry.inherited if not label_allowed(label))
        if outside:
            return "code-only profile: rests on " + ", ".join(outside)
        return None


def load_build_manifest(path: str | Path) -> CodeOnlyProfile:
    """``{"format": "tdo-code-only-build/1", "language_id", "abi_tag",
    "libraries": {"<file name>": "<sha256 hex>"}}``."""
    data = Path(path).read_bytes()
    raw = json.loads(data)
    if type(raw) is not dict or set(raw) - {"notes"} != {"format", "language_id", "abi_tag", "libraries"} \
            or raw["format"] != MANIFEST_FORMAT:
        raise ProfileError(f"{path}: a build manifest is {{format: {MANIFEST_FORMAT}, language_id, abi_tag, "
                           "libraries, notes?}")
    libraries = raw["libraries"]
    if type(libraries) is not dict or any(
            type(name) is not str or type(sha) is not str or len(sha) != 64
            or any(c not in "0123456789abcdef" for c in sha) for name, sha in libraries.items()):
        raise ProfileError(f"{path}: libraries maps file names to lower-case sha256 hex")
    upper = {name.upper(): sha for name, sha in libraries.items()}
    if len(upper) != len(libraries):
        raise ProfileError(f"{path}: a library named twice")
    if type(raw["language_id"]) is not str or type(raw["abi_tag"]) is not str:
        raise ProfileError(f"{path}: language_id / abi_tag are strings")
    return CodeOnlyProfile(raw["language_id"], raw["abi_tag"], tuple(sorted(upper.items())),
                           hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest())


__all__ = ("ALLOWED_LABELS", "ALLOWED_PREFIXES", "CodeOnlyProfile", "MANIFEST_FORMAT", "MODEL_OFF", "ON",
           "ProfileError", "forced_arguments", "label_allowed", "load_build_manifest", "switch_vector")
