"""Layer rows of ``bundle_lint`` (design G0 r0..r6), computed in the diagnosis
process from the claims of ``diagnose.py`` -- engine functions are called,
never re-implemented.

Layer 1 ``transport``: admission, program scope, image-info, block write
flags (read-only image folding, r5 section 4), per-function scope and naming.
Layer 2 ``operations`` and layer 3 ``features``: ``ops_layer.py``,
``feature_layer.py``.
"""

from __future__ import annotations

from pathlib import Path

from report import Row, source_row_key


def _function_key(claim) -> str:
    # (a refused member may lack nothing but its index: the manifest id is kept when known)
    return claim.function_id if claim.function_id else source_row_key("unknown", claim.index)


def transport_rows(diagnosis) -> list[Row]:
    rows = []
    admission = diagnosis.admission
    if not admission.get("ok"):
        rows.append(Row("transport", "admission", "bundle", "evaluated", "refused", "engine",
                        {"error": admission["error"]}))
        return rows
    rows.append(Row("transport", "admission", "bundle", "evaluated", "applied", "engine"))
    program = diagnosis.program
    if program.get("ok"):
        rows.append(Row("transport", "program", "bundle", "evaluated", "applied", "engine",
                        {"digest": program["digest"]}))
    else:
        rows.append(Row("transport", "program", "bundle", "evaluated", "refused", "engine",
                        {"stage": program["stage"], "reason": program["reason"]}))
    image = diagnosis.image_info
    if not image.get("ok"):
        rows.append(Row("transport", "image_info", "bundle", "evaluated", "refused", "engine",
                        {"error": image["error"]}))
    elif not image["present"]:
        rows.append(Row("transport", "image_info", "bundle", "evaluated", "not_applicable", "engine"))
    else:
        rows.append(Row("transport", "image_info", "bundle", "evaluated", "applied", "engine"))
        for block in diagnosis.image_info_value.blocks:
            # ReadOnlyImage.value's block condition (image_info.py:154, pinned by a
            # guard test); import slots inside a folding block are excluded per
            # address by value() itself -- readonly_use rows show actual uses
            folds = block.initialized and block.read and not block.write and not block.volatile
            rows.append(Row("transport", "readonly_block", f"{block.space_id}:{block.start:x}", "evaluated",
                            "applied" if folds else "not_applicable", "lint",
                            {"name": block.name, "size": block.size, "read": block.read, "write": block.write,
                             "volatile": block.volatile, "initialized": block.initialized,
                             "import_slots": sum(1 for row in diagnosis.image_info_value.imports
                                                 for space, offset in row.slots
                                                 if space == block.space_id
                                                 and block.start <= offset < block.start + block.size)}))
    for claim in diagnosis.claims:
        key = _function_key(claim)
        detail = {"index": claim.index, "observation_member": claim.observation_member,
                  "observation_sha256": claim.observation_sha256}
        if claim.scope == "constructed":
            rows.append(Row("transport", "function_scope", key, "evaluated", "applied", "engine",
                            {**detail, "entry": claim.entry}))
        else:
            rows.append(Row("transport", "function_scope", key, "evaluated", "refused", "engine",
                            {**detail, "reason": claim.scope_reason}))
        if claim.scope == "constructed":
            if claim.seeds == "ok":
                rows.append(Row("transport", "seeds", key, "evaluated", "applied", "engine"))
            else:
                rows.append(Row("transport", "seeds", key, "evaluated", "refused", "engine",
                                {"error": claim.seeds_error}))
        else:
            rows.append(Row("transport", "seeds", key, "not_reached"))
        if claim.naming == "ok":
            rows.append(Row("transport", "naming", key, "evaluated", "applied", "engine"))
        elif claim.naming == "error":
            rows.append(Row("transport", "naming", key, "evaluated", "refused", "engine",
                            {"error": claim.naming_error}))
        else:
            rows.append(Row("transport", "naming", key, "not_reached"))
    if diagnosis.fatal is not None:
        rows.append(Row("transport", "scoped_iterator", "bundle", "evaluated", "refused", "engine",
                        diagnosis.fatal))
    return rows


def rows(diagnosis, generation: Path, options: dict) -> list[Row]:
    import feature_layer
    import ops_layer

    out = transport_rows(diagnosis)
    if diagnosis.admission.get("ok"):
        # design checks G0 leaves out (README "Not in G0"): visible, never silently absent
        out.append(Row("operations", "excluded", "ignored_keys_and_proof_fields", "not_run", None, "lint",
                       {"why": "needs the engine to expose the observation key sets it reads (design r0 s5-6, r1 s4)"}))
        out.extend(ops_layer.rows(diagnosis, generation, options))
        out.extend(feature_layer.rows(diagnosis, generation, options))
    return out
