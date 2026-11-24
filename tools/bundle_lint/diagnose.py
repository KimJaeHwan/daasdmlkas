"""The diagnosis pass of ``bundle_lint`` (design G0 r0..r6).

A second fresh admission in its own process. Every function is claimed once,
guarded: its scope result, observation identity and call naming are obtained
together, and a failure of one function is recorded instead of stopping the
pass. From the same claims the pass predicts where each pipeline path stops
(in manifest = session order) and with which exception, so a path's actual
stop can be checked (r4 section 2): a mismatch is ``error``.

The engine's public entry would stop at the first failure; this pass drives
the session's own per-function steps (the scoped iterator, role capture and
``_decode_function``) so every function is seen. Guard tests pin those
internals (tests/intra/test_bundle_lint.py).

Everything runs inside ``resource_limits.run_analysis`` (r6 section 1): the
same worker the public entries use; the session stays on that thread.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

STRICT_SCOPE_MESSAGE = "observed function scope could not be constructed"
PROGRAM_MESSAGE = "Bundle program scope is unresolved"


def _error(error: BaseException) -> dict:
    return {"class": f"{type(error).__module__}.{type(error).__qualname__}", "message": str(error)}


@dataclass
class FunctionClaim:
    index: int
    function_id: str | None = None
    observation_member: str | None = None
    observation_sha256: str | None = None
    scope: str = "unknown"                 # constructed | unresolved | not_claimed
    scope_reason: str | None = None
    entry: str | None = None
    seeds: str = "not_run"                # ok | error | not_run (call / tail seeds, before naming)
    seeds_error: dict | None = None
    naming: str = "not_run"               # ok | error | not_run
    naming_error: dict | None = None
    unit: object = None                   # (in-process only)
    evidence: object = None

    def as_json(self) -> dict:
        out = {name: getattr(self, name) for name in (
            "index", "function_id", "observation_member", "observation_sha256", "scope", "scope_reason",
            "entry", "seeds", "seeds_error", "naming", "naming_error")}
        return {key: value for key, value in out.items() if value is not None}


@dataclass
class Diagnosis:
    admission: dict = field(default_factory=dict)
    program: dict = field(default_factory=dict)
    image_info: dict = field(default_factory=dict)
    claims: list = field(default_factory=list)
    fatal: dict | None = None             # a transport / hash failure that stopped the scoped iterator
    image_info_value: object = None       # (in-process only)
    program_value: object = None

    def as_json(self) -> dict:
        out = {"admission": self.admission, "program": self.program, "image_info": self.image_info,
               "claims": [claim.as_json() for claim in self.claims]}
        if self.fatal is not None:
            out["fatal"] = self.fatal
        return out


def diagnose(generation, naming_source, *, keep=None) -> Diagnosis:
    """The whole pass on the analysis worker. ``keep(diagnosis)`` runs inside the
    open session (layers 2-3 read the evidences there)."""
    from engine_api import run_analysis

    return run_analysis(_diagnose, Path(generation), Path(naming_source), keep)


def _diagnose(generation: Path, naming_source: Path, keep) -> Diagnosis:
    from engine_api import ConstructedFunctionScope, ConstructedProgramScope
    from engine_api import FunctionCallSeedUnit
    from engine_api import seed_function_calls, seed_tail_calls
    from engine_api import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from engine_api import load_image_info
    from engine_api import admit_frozen_bundle
    from engine_api import open_observed_function_session

    result = Diagnosis()
    binding = NamingBindingExpectation(sha256(naming_source.read_bytes()).digest(), CALL_NAMING_GHIDRA_VERSION)
    from engine_api import RESOURCE_FAILURES

    try:
        snapshot = admit_frozen_bundle(generation)
        session = open_observed_function_session(snapshot, naming_binding=binding)
        session.__enter__()
    except RESOURCE_FAILURES as error:   # (a resource failure is no verdict on the Bundle: Astra impl r2 P2)
        result.admission = {"ok": False, "resource": True, "error": _error(error)}
        return result
    except Exception as error:
        result.admission = {"ok": False, "error": _error(error)}
        return result
    result.admission = {"ok": True}
    try:
        program = session.program_result
        result.program_value = program
        if type(program) is ConstructedProgramScope:
            result.program = {"ok": True, "digest": program.scope.digest.hex()}
        else:
            result.program = {"ok": False, "stage": program.stage.value, "reason": program.reason.value}
        try:
            result.image_info_value = load_image_info(generation)
            result.image_info = {"ok": True, "present": result.image_info_value is not None}
        except Exception as error:
            result.image_info = {"ok": False, "error": _error(error),
                                 "resource": isinstance(error, RESOURCE_FAILURES)}
        if type(program) is not ConstructedProgramScope:
            # (the envelope captures no function roles then; every path stops at
            # the program -- Astra impl r1 P2)
            if keep is not None:
                keep(result)
            return result
        import engine_api

        adapter, scoped = engine_api.scoped_functions(session)
        index = 0
        while True:
            claim = FunctionClaim(index)
            try:
                unit = next(scoped)
            except StopIteration:
                break
            except Exception as error:
                result.fatal = {"index": index, "error": _error(error), "resource": isinstance(error, RESOURCE_FAILURES)}
                break
            try:
                captured = adapter.collect_function_roles()
            except Exception as error:
                result.fatal = {"index": index, "error": _error(error), "resource": isinstance(error, RESOURCE_FAILURES)}
                break
            identity = captured.transport_identity
            member = identity.observation_member
            claim.function_id = identity.function_id
            claim.observation_member = member.member_id
            claim.observation_sha256 = member.sha256_digest.hex()
            claim.unit = unit
            function = unit.scopes.function
            if type(function) is ConstructedFunctionScope:
                claim.scope = "constructed"
                claim.entry = f"{function.entry.space_id:x}:{function.entry.byte_offset:x}"   # (function_key)
                # the steps of _decode_function, the seeds first: a seed failure is
                # not a naming failure (Fable / Astra impl r1 P2)
                try:
                    seeds = seed_function_calls(unit)
                    if type(seeds) is not FunctionCallSeedUnit:
                        raise ValueError("observed function call seeds could not be constructed")
                    seed_tail_calls(unit)
                    claim.seeds = "ok"
                except Exception as error:
                    claim.seeds = "error"
                    claim.seeds_error = {**_error(error), "resource": isinstance(error, RESOURCE_FAILURES)}
                if claim.seeds == "ok":
                    try:
                        claim.evidence = engine_api.decode_function(session, unit, captured)
                        claim.naming = "ok"
                    except Exception as error:
                        claim.naming = "error"
                        claim.naming_error = {**_error(error), "resource": isinstance(error, RESOURCE_FAILURES)}
            else:
                claim.scope = "unresolved"
                claim.scope_reason = function.reason.value
            result.claims.append(claim)
            index += 1
        if keep is not None:
            keep(result)
    finally:
        session.__exit__(None, None, None)
    return result


# -- stop predictions (r4 section 2, r5, r6) ---------------------------------------------

def predict(diagnosis: Diagnosis) -> dict:
    """{path: None (no stop) | {"stage", "index"?, "function_id"?, "class", "message"}}.

    Order of the summary entry: admission, program, image-info, then the
    function iterator (strict: first scope refusal or naming failure; retain:
    first naming failure). base_graph: admission, program (``iter_outcomes``),
    first naming failure; image-info is not read."""
    out = {}
    for path in ("summary", "summary-retain", "base_graph"):
        out[path] = _predict(diagnosis, path)
    return out


DUPLICATE_MESSAGE = "duplicate base graph function key"


def _predict(diagnosis: Diagnosis, path: str):
    if not diagnosis.admission.get("ok"):
        return {"stage": "admission", **diagnosis.admission["error"]}
    if not diagnosis.program.get("ok"):
        return {"stage": "program", "class": "builtins.ValueError", "message": PROGRAM_MESSAGE}
    if path != "base_graph" and not diagnosis.image_info.get("ok"):
        return {"stage": "image_info", **diagnosis.image_info["error"]}   # (class, message)
    for claim in diagnosis.claims:
        if claim.scope == "unresolved" and path == "summary":
            return {"stage": "function", "index": claim.index, "function_id": claim.function_id,
                    "class": "builtins.ValueError", "message": STRICT_SCOPE_MESSAGE}
        if claim.seeds == "error":
            return {"stage": "function", "index": claim.index, "function_id": claim.function_id,
                    "class": claim.seeds_error["class"], "message": claim.seeds_error["message"]}
        if claim.naming == "error":
            return {"stage": "function", "index": claim.index, "function_id": claim.function_id,
                    "class": claim.naming_error["class"], "message": claim.naming_error["message"]}
    if diagnosis.fatal is not None:
        return {"stage": "transport", "index": diagnosis.fatal["index"], **diagnosis.fatal["error"]}   # (class, message)
    if path == "base_graph":
        # BaseGraphPublication refuses two admitted members with one entry
        # (base_graph.py:175); the summary keeps the last one silently
        entries = [claim.entry for claim in diagnosis.claims if claim.evidence is not None]
        if len(set(entries)) != len(entries):
            return {"stage": "publication", "class": "builtins.ValueError", "message": DUPLICATE_MESSAGE}
    return None


def pre_analysis(prediction) -> bool:
    """Whether a predicted stop comes before any function is analysed."""
    return prediction is not None and prediction["stage"] in (
        "admission", "program", "image_info", "function", "transport", "publication")


def check_stop(prediction, child: dict) -> tuple[str, str | None, dict]:
    """(run_state, verdict, detail) of one path's stop row, ``source: lint``.

    The stop index is restored by the diagnosis (``source: lint``); the child's
    actual exception must match the predicted class and message, else ``error``."""
    if child.get("run_state") != "evaluated":
        return child.get("run_state", "error"), None, {"child": child}
    actual = child.get("exception")
    detail = {"predicted": prediction, "actual": actual}
    if prediction is None and child.get("completed"):
        return "evaluated", "not_applicable", detail     # (no stop)
    if prediction is not None and actual is not None and \
            (prediction["class"], prediction["message"]) == (actual["class"], actual["message"]):
        return "evaluated", "applied", detail            # (stopped where and how predicted)
    return "error", None, detail


def child_main(argv) -> int:
    """``diagnose.py <generation> <naming_source> [json options]`` -> one JSON line:
    the diagnosis, the stop predictions and the layer rows."""
    import json
    import sys

    generation, naming_source = argv[:2]
    options = json.loads(argv[2]) if len(argv) > 2 else {}
    rows = []

    def keep(diagnosis):
        import layers

        rows.extend(row.as_json() for row in layers.rows(diagnosis, Path(generation), options))

    diagnosis = diagnose(generation, naming_source, keep=keep)
    if not diagnosis.admission.get("ok"):
        import layers

        rows.extend(row.as_json() for row in layers.rows(diagnosis, Path(generation), options))
    sys.stdout.write(json.dumps({"diagnosis": diagnosis.as_json(), "predictions": predict(diagnosis),
                                 "rows": rows}, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(child_main(sys.argv[1:]))
