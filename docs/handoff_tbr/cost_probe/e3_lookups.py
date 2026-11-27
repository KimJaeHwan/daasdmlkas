"""E3 (design_tbr_g2a_cost r1 s4, r2 D3): bind one evidence file with one code tree's bind_common_facts and hash
the answer to every unit's query (plus one absent-path query per row).

usage: e3_lookups.py <code_tree> <generation> <evidence> <facts>
The query list comes from the evidence's own units (-4 rows or expanded -5 sets); E1 already proved the two lists
equal, so equal digests across trees / files mean equal answers.
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

TREE, GEN, EV, FACTS = (Path(x) for x in sys.argv[1:5])
sys.path[:0] = [str(TREE / "src"), str(TREE / "tools/decode_check")]
import check  # noqa: E402
import common_facts as cf  # noqa: E402
import decode_check  # noqa: E402
import evidence  # noqa: E402
import lifting  # noqa: E402
import producer_override  # noqa: E402

document = evidence.parse(EV.read_bytes())
facts_doc = json.loads(FACTS.read_bytes())
facts = decode_check.collect(GEN, TREE / "ghidra" / "GhidraV2CallNaming.java")
manifest = json.loads((GEN / "manifest.json").read_bytes())
members = {row["id"]: row for row in manifest["members"]}
seal = json.loads((GEN / "seal.json").read_bytes())
view = {"generation_id": seal["generation_id"], "manifest_sha256": seal["manifest_sha256"],
        "original_sha256": members["original"]["sha256"],
        "functions": {row["id"]: {"observation_sha256": members[row["observation_member"]]["sha256"],
                                  "rows": set(), "kept": True} for row in manifest["functions"]}}
original_path = next(r["path"] for r in manifest["members"] if r["id"] == manifest["original_member_id"])
original = (GEN / original_path).read_bytes()
image = check.Image(GEN, check.parse_original(original), facts["image_base"], original)
view["producer_profile"] = manifest.get("producer_profile")
observations = {}
for function in facts["functions"]:
    entry = view["functions"][function["function_id"]]
    entry["rows"] = {(r["space"], r["address"]) for r in function["rows"]}
    entry["override_report"] = None if function.get("producer_profile") is None else {
        (r["space"], r["address"]): {"present": producer_override.present(r["override"]),
                                     "pin": producer_override.shape_code(r, lifting.identify(r),
                                                                         image.window(r["address"], r["space"])["bytes"])}
        for r in function["rows"]}
    for r in function["rows"]:
        observations[cf.identity(r, function["function_id"])] = r
del facts

lookup = evidence.bind_common_facts(document, facts_doc, bundle=view, allowlist=[evidence.allowlist_entry(document)],
                                    observations=observations)
# (Astra impl r1 item 1) the same invalid document must be rejected by every reader
block = document["common_facts"]
first = block["rows"][0]
saved = first["state"]
first["state"] = "invalid-aggregate"
try:
    try:
        evidence.bind_common_facts(document, facts_doc, bundle=view, allowlist=[evidence.allowlist_entry(document)],
                                   observations=observations)
    except evidence.Rejected:
        print("rejects an invalid row aggregate")
    else:
        raise AssertionError("reader accepted an invalid row aggregate")
finally:
    first["state"] = saved
if block.get("schema") == "tbr-common-facts-verdicts-2":
    units_of = cf.block_units(block)
else:
    def units_of(vr):
        return vr["units"]
h, answers, n = hashlib.sha256(), Counter(), 0
for vr in block["rows"]:
    row = {"id": vr["id"], "observation": vr["observation"]}
    queries = [dict(row=row, path="transfer.not_a_field")]
    for u in units_of(vr):
        q = dict(row=row, path=u["path"])
        if "edge" in u:
            q["edge"] = u["edge"]
        if "op" in u:
            q["op"] = u["op"]
            queries.append(dict(q, op=dict(u["op"], row=row)))      # (Fable impl r1 P2-1: explicit owner)
        queries.append(q)
    for q in queries:
        a = lookup(q)
        answers[a] += 1
        n += 1
        h.update(json.dumps(q, sort_keys=True).encode() + b"\t" + json.dumps(a).encode() + b"\n")
print("queries", n, "answers", dict(answers))
print("DIGEST", h.hexdigest())
