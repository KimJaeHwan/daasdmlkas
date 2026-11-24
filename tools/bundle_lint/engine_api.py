"""The engine surface ``bundle_lint`` uses -- one place, so a Rust engine port
(.census6/rust_port_plan_final.md: PyO3 kernels behind per-module switches,
Python orchestration) knows exactly what the lint needs from it.

Every engine name the tool touches is listed in ``SURFACE`` with its role:

- ``entry``   public entry points (admission, session, summary, base graph)
- ``contract`` wire / identity types and encoders of the Bundle format
- ``fact``    recognisers and decisions whose answers the lint reports; a Rust
              kernel must keep them callable (or export the same facts)
- ``context`` Python context variables the summary sets around its run; a Rust
              engine replaces them with an explicit options value
- ``internal`` private helpers or session internals the lint drives today;
              each is pinned by a guard test and is a candidate public API

Names resolve lazily (PEP 562), so importing this module never imports the
engine (Windows can import the tool; admission needs POSIX). No other file
of tools/bundle_lint imports ``tdo_v2`` (guard test).
"""

from __future__ import annotations

import importlib

# name -> (module, attribute or None for the module itself, role)
SURFACE = {
    # -- entry
    "admit_frozen_bundle": ("tdo_v2.integration.configured_bundle", "admit_frozen_bundle", "entry"),
    "open_observed_function_session": ("tdo_v2.integration.observed_function_session",
                                       "open_observed_function_session", "entry"),
    "analyze_frozen_bundle_with_summaries": ("tdo_v2.summary_engine", "analyze_frozen_bundle_with_summaries", "entry"),
    "build_frozen_bundle_graphs": ("tdo_v2.base_graph", "build_frozen_bundle_graphs", "entry"),
    "load_image_info": ("tdo_v2.image_info", "load_image_info", "entry"),
    "ReadOnlyImage": ("tdo_v2.image_info", "ReadOnlyImage", "entry"),
    "FunctionNormalizer": ("tdo_v2.normalize", "FunctionNormalizer", "entry"),
    "NormalizedFunction": ("tdo_v2.normalize", "NormalizedFunction", "entry"),
    "NullBoundaryProvider": ("tdo_v2.boundary", "NullBoundaryProvider", "entry"),
    "load_pcodeop_models": ("tdo_v2.pcodeop_models", "load_pcodeop_models", "entry"),
    "run_analysis": ("tdo_v2.resource_limits", "run_analysis", "entry"),
    "last_run": ("tdo_v2.resource_limits", "last_run", "entry"),
    "resource_limits": ("tdo_v2.resource_limits", None, "entry"),
    "RESOURCE_FAILURES": ("tdo_v2.resource_limits", "RESOURCE_FAILURES", "entry"),
    "ANALYSIS_FAILURES": ("tdo_v2.interprocedural", "ANALYSIS_FAILURES", "entry"),
    "ANALYSIS_RECURSION_LIMIT": ("tdo_v2.interprocedural", "ANALYSIS_RECURSION_LIMIT", "context"),
    # -- contract (Bundle wire format, naming sidecar, scope result types)
    "AddressCoordinate": ("tdo_v2._scope_contracts", "AddressCoordinate", "contract"),
    "ValidatedVarnode": ("tdo_v2._scope_contracts", "ValidatedVarnode", "contract"),
    "VarnodeKindCode": ("tdo_v2._scope_contracts", "VarnodeKindCode", "contract"),
    "ConstructedFunctionScope": ("tdo_v2._scope_results", "ConstructedFunctionScope", "contract"),
    "ConstructedProgramScope": ("tdo_v2._scope_results", "ConstructedProgramScope", "contract"),
    "FunctionCallSeedUnit": ("tdo_v2.call_contracts", "FunctionCallSeedUnit", "contract"),
    "CALL_NAMING_EXPORTER_REVISION": ("tdo_v2.configured_naming_contracts", "CALL_NAMING_EXPORTER_REVISION", "contract"),
    "CALL_NAMING_GHIDRA_VERSION": ("tdo_v2.configured_naming_contracts", "CALL_NAMING_GHIDRA_VERSION", "contract"),
    "CALL_NAMING_INVENTORY_COMPLETENESS": ("tdo_v2.configured_naming_contracts",
                                           "CALL_NAMING_INVENTORY_COMPLETENESS", "contract"),
    "CALL_NAMING_SCHEMA_ID": ("tdo_v2.configured_naming_contracts", "CALL_NAMING_SCHEMA_ID", "contract"),
    "CALL_NAMING_SCHEMA_VERSION": ("tdo_v2.configured_naming_contracts", "CALL_NAMING_SCHEMA_VERSION", "contract"),
    "CapturedNamingAlias": ("tdo_v2.configured_naming_contracts", "CapturedNamingAlias", "contract"),
    "CapturedNamingResolution": ("tdo_v2.configured_naming_contracts", "CapturedNamingResolution", "contract"),
    "CapturedNamingRow": ("tdo_v2.configured_naming_contracts", "CapturedNamingRow", "contract"),
    "CapturedNamingTarget": ("tdo_v2.configured_naming_contracts", "CapturedNamingTarget", "contract"),
    "NamingAliasKind": ("tdo_v2.configured_naming_contracts", "NamingAliasKind", "contract"),
    "NamingBindingExpectation": ("tdo_v2.configured_naming_contracts", "NamingBindingExpectation", "contract"),
    "NamingOpcode": ("tdo_v2.configured_naming_contracts", "NamingOpcode", "contract"),
    "NamingResolutionState": ("tdo_v2.configured_naming_contracts", "NamingResolutionState", "contract"),
    "NamingSourceQuality": ("tdo_v2.configured_naming_contracts", "NamingSourceQuality", "contract"),
    "NamingUnresolvedReason": ("tdo_v2.configured_naming_contracts", "NamingUnresolvedReason", "contract"),
    "naming_content_digest": ("tdo_v2.configured_naming_contracts", "naming_content_digest", "contract"),
    "naming_row_digest": ("tdo_v2.configured_naming_contracts", "naming_row_digest", "contract"),
    "naming_target_digest": ("tdo_v2.configured_naming_contracts", "naming_target_digest", "contract"),
    "CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID": ("tdo_v2.configured_profile_contracts",
                                             "CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID", "contract"),
    "CONFIGURED_BUNDLE_SEAL_SCHEMA_ID": ("tdo_v2.configured_profile_contracts", "CONFIGURED_BUNDLE_SEAL_SCHEMA_ID",
                                         "contract"),
    # -- fact (recognisers / decisions the lint reports)
    "seed_function_calls": ("tdo_v2.call_seeds", "seed_function_calls", "fact"),
    "seed_tail_calls": ("tdo_v2.call_seeds", "seed_tail_calls", "fact"),
    "call_relations": ("tdo_v2.call_relations", "call_relations", "fact"),
    "observed_call_state_projections": ("tdo_v2.observed_call_state", "observed_call_state_projections", "fact"),
    "call_like_instruction": ("tdo_v2.control_projection", "call_like_instruction", "fact"),
    "control_successor_coordinates": ("tdo_v2.control_projection", "control_successor_coordinates", "fact"),
    "site_key": ("tdo_v2.control_context", "site_key", "fact"),
    "unknown_transfer_sites": ("tdo_v2.control_context", "unknown_transfer_sites", "fact"),
    "program_switches_stack": ("tdo_v2.interprocedural", "program_switches_stack", "fact"),
    "refinements_for": ("tdo_v2.intrinsic_refinements", "refinements_for", "fact"),
    "isa_identity": ("tdo_v2.isa_identity", None, "fact"),
    "no_effect_calls": ("tdo_v2.pcodeop_models", "no_effect_calls", "fact"),
    "trap_operations": ("tdo_v2.pcodeop_models", "trap_operations", "fact"),
    "rep_sites": ("tdo_v2.rep_strings", "rep_sites", "fact"),
    "is_native_call": ("tdo_v2._scope_contracts", "is_native_call", "fact"),
    # -- context (the summary's execution context: interprocedural.py:282-288)
    "IMPORT_SLOTS": ("tdo_v2.relative_memory", "IMPORT_SLOTS", "context"),
    "ImportSlots": ("tdo_v2.relative_memory", "ImportSlots", "context"),
    "ENTRY_VALUES_NOT_FRAME": ("tdo_v2.may_alias", "ENTRY_VALUES_NOT_FRAME", "context"),
    "OPAQUE_NO_STACK_ADDRESSES": ("tdo_v2.may_alias", "OPAQUE_NO_STACK_ADDRESSES", "context"),
    "PRE_ESCAPE_NOT_FRAME": ("tdo_v2.may_alias", "PRE_ESCAPE_NOT_FRAME", "context"),
    "OPAQUE_RESTORES_SP": ("tdo_v2.call_clobber", "OPAQUE_RESTORES_SP", "context"),
    # -- internal (private; guard-pinned; candidates for a public API)
    "_operation_key": ("tdo_v2.call_seeds", "_operation_key", "internal"),
    "_edges": ("tdo_v2.control_context", "_edges", "internal"),
    "_safe_name": ("tdo_v2.integration.configured_bundle", "_safe_name", "internal"),
    "_selected_resolved_target": ("tdo_v2.integration.configured_target_resolution", "_selected_resolved_target",
                                  "internal"),
    "_failure_reason": ("tdo_v2.interprocedural", "_failure_reason", "internal"),
    "_plain_push_call": ("tdo_v2.interprocedural", "_plain_push_call", "internal"),
    "_program_memory_space": ("tdo_v2.interprocedural", "_program_memory_space", "internal"),
    "_return_shape": ("tdo_v2.may_alias", "_return_shape", "internal"),
    "_stack_pointer": ("tdo_v2.may_alias", "_stack_pointer", "internal"),
    "_unit_stub": ("tdo_v2.may_alias", "_unit_stub", "internal"),
    "_coordinate_key": ("tdo_v2.normalize", "_coordinate_key", "internal"),
    "_landing_pads": ("tdo_v2.pcode_blocks", "_landing_pads", "internal"),
    "_x86_64": ("tdo_v2.summary_engine", "_x86_64", "internal"),
}

ROLES = ("entry", "contract", "fact", "context", "internal")


def __getattr__(name: str):
    row = SURFACE.get(name)
    if row is None:
        raise AttributeError(f"engine_api has no {name!r} (add it to SURFACE with its role)")
    module = importlib.import_module(row[0])
    return module if row[1] is None else getattr(module, row[1])


# -- session internals (internal): the diagnosis pass claims every function itself ------------

def scoped_functions(session):
    """(role adapter, scoped unit iterator) of an open session -- the steps of
    ``_ObservedFunctionIterator.__next__`` the diagnosis drives one by one
    (observed_function_session.py; pinned by the session guard tests)."""
    adapter = session._provider_adapter
    scoped = session._envelope.iter_scoped_functions()
    session._iterator_claimed = True   # (the session's own iterator is not used after this)
    return adapter, scoped


def decode_function(session, unit, captured):
    """``ObservedFunctionSession._decode_function`` (seeds, tails, naming)."""
    return session._decode_function(unit, captured)


# -- run internals (internal): the results the summary passes to control_contexts ---------------

def run_control_context_inputs(generation, naming_source):
    """Run the summary (NullBoundaryProvider) and return the ``(results, failed)``
    it passes to ``control_contexts`` (summary_engine.py:767), or ``None`` when
    the run raises or never gets there. Today by wrapping the module attribute
    for the duration of the run (guard-pinned call line); a Rust engine should
    expose these per-function results (calls, multi_calls, observation) as a
    public run output instead."""
    summary_engine = importlib.import_module("tdo_v2.summary_engine")
    boundary = importlib.import_module("tdo_v2.boundary")
    captured = {}
    original = summary_engine.control_contexts

    def capture(results, failed, *args, **kwargs):
        captured["value"] = (results, failed)
        return original(results, failed, *args, **kwargs)

    summary_engine.control_contexts = capture
    try:
        summary_engine.analyze_frozen_bundle_with_summaries(
            generation, naming_exporter_source=naming_source, boundary_provider=boundary.NullBoundaryProvider())
    except Exception:   # (no result to read edges from: the caller refuses the variant)
        return None
    finally:
        summary_engine.control_contexts = original
    return captured.get("value")
