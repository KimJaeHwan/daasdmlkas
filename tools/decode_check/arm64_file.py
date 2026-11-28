"""Bind A64 snapshot words to the original ELF and record modeled loader writes."""

from collections import Counter
import hashlib

from arm64_decode import ObserverError, bind_snapshot_rows, require_basis
from arm64_facts import Arm64Facts
from check import Intervals
import common_facts as cf
import elf_map


def original_member(manifest, data):
    member = next(m for m in manifest["members"] if m["id"] == manifest["original_member_id"])
    if member["size"] != len(data) or member["sha256"] != hashlib.sha256(data).hexdigest():
        raise ObserverError("original member differs from the admitted snapshot")
    return {k: member[k] for k in ("id", "size", "sha256")}


class FileMapping:
    def __init__(self, data, image_space, base, page):
        mapping = self.mapping = elf_map.parse(data, arm64_page=page)
        self.data, self.space, self.base = data, image_space, base
        self.bias = base - mapping.image_base
        self.reason = None
        if not mapping.ok:
            self.reason = mapping.why
        elif mapping.fixed_base and self.bias:
            self.reason = "ET_EXEC snapshot is outside its linked base"
        elif self.bias % page:
            self.reason = "load bias is unaligned under the selected page model"
        elif any(s["align"] > 1 and self.bias % s["align"] for s in mapping.segments):
            self.reason = "load bias does not preserve PT_LOAD p_align congruence"
        elif invalid := next((s for s in mapping.segments if s["state"] != "mapped"), None):
            self.reason = f"PT_LOAD[{invalid['index']}]: {invalid['why']}"
        elif any(base + r.start < 0 or base + r.end > elf_map.U64_END for r in mapping.ranges):
            self.reason = "loaded mapping extends outside the 64-bit address space"
        self.executable = [s for s in mapping.segments if s["state"] == "mapped" and s["flags"] & 1]
        self.writes = Intervals(mapping.written.ranges)

    def word(self, request):
        space, address, word = request
        if self.reason:
            return {"state": "unobserved", "reason": self.reason}
        if space != self.space:
            return {"state": "unobserved", "reason": "row is outside the admitted image address space"}
        rva = address - self.base
        span = self.mapping.at(rva)
        if span is None:
            return {"state": "unobserved", "reason": "outside PT_LOAD mapping"}
        if span.kind != "file" or rva + 4 > span.end:
            return {"state": "unobserved", "reason": span.why or "word is not in one file-backed span"}
        va = address - self.bias
        segments = [s for s in self.executable if s["vaddr"] <= va and va + 4 <= s["vaddr"] + s["filesz"]]
        if len(segments) != 1:
            return {"state": "unobserved", "reason": "word lacks a unique file-backed executable PT_LOAD"}
        segment, = segments
        offset = segment["offset"] + va - segment["vaddr"]
        expected = self.data[offset:offset + 4]
        observed = word.to_bytes(4, "little")
        labels = {label for byte in range(rva, rva + 4) if (hit := self.writes.find(byte)) for label in hit[2]}
        if labels:
            loader = {"state": "possible_write", "sources": sorted(labels)}
        elif self.mapping.written.state == "indeterminate":
            loader = {"state": "unobserved"}
        else:
            loader = {"state": "no_modeled_write"}
        return {"state": "match" if expected == observed else "mismatch",
                "file_offset": offset, "program_header_index": segment["index"],
                "file_bytes": expected.hex(), "loader": loader}


def diagnose(document, raw, original, *, admitted_bundle, manifest_bytes, blocks, binding, complete,
             image_space, base, page):
    try:
        manifest, _ = bind_snapshot_rows(document, raw, admitted_bundle=admitted_bundle,
                                        manifest_bytes=manifest_bytes, blocks=blocks, binding=binding)
        member = original_member(manifest, original)
    except ObserverError as error:
        return {"status": "error", "error": str(error), "observation_rows": len(document["rows"])}

    image = FileMapping(original, image_space, base, page)
    basis = Arm64Facts(blocks, {}, {})
    rows = []
    counts, loader_counts = Counter(), Counter()
    for row in document["rows"]:
        request, reason = require_basis(row, raw[cf.rr(row)], basis)
        result = image.word(request) if request is not None else {"state": "unobserved", "reason": reason}
        counts[result["state"]] += 1
        loader_counts[result.get("loader", {}).get("state", "unobserved")] += 1
        rows.append(dict(row=cf.ref(row), basis=row["aarch64"]["basis"], **result))
    mapping = image.mapping
    return dict(status="unsupported" if image.reason else "ok", reason=image.reason, rule=mapping.rules,
                bundle=document["bundle"], binding=binding, original=member,
                mapping_id=mapping.mapping_id, page_size=page, image_space=image_space, snapshot_base=f"{base:x}",
                linked_base=f"{mapping.image_base:x}" if mapping.ok else None,
                load_bias=image.bias if mapping.ok else None, loader_inventory=mapping.written.state,
                loader_reason=mapping.written.why or None, observation_complete=complete,
                observation_rows=len(rows), file_counts=dict(counts), loader_counts=dict(loader_counts), rows=rows)
