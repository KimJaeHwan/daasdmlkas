"""Canonical byte encoding of runtime path identities and physical spans."""

from __future__ import annotations

import json


def wire(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def span_fact(span):
    if span is None:
        return None
    return {
        "object_kind": span.object_id.kind.value,
        "scope_kind": span.object_id.scope.kind.value,
        "scope_digest": span.object_id.scope.digest.hex(),
        "space_key": span.object_id.space_key,
        "start": span.start,
        "size": span.size,
    }
