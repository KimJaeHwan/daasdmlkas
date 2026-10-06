#!/usr/bin/env bash
# DataFlowBench 64-case metric for one Bundle generation, default and TEST-ONLY
# assumed-boundary modes. Run in WSL.
# usage: dfbench_metric.sh <generation> <tag> [binary]
# Prints, per mode, counts of (exact|missing|extra-only, sure|unsure);
# "missing + sure" must stay 0.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
G=$1; TAG=$2; BIN=${3:-dfbench_win_core}
M=/mnt/d/01_gitproject/09_tdo_testbed/manifests/cases_manifest.json
mkdir -p /root/tdo_compare
cd "$REPO"
~/venvs/tdo/bin/python tools/bundle_export/run_dfbench.py "$G" --expected "$M" --binary "$BIN" \
    --json "/root/tdo_compare/$TAG.current.json" > "/root/tdo_compare/$TAG.current.log" 2>&1
~/venvs/tdo/bin/python tools/bundle_export/run_dfbench.py "$G" --expected "$M" --binary "$BIN" \
    --assume-boundary-effects \
    --json "/root/tdo_compare/$TAG.assumed.json" > "/root/tdo_compare/$TAG.assumed.log" 2>&1
python3 - "$M" "$TAG" "$BIN" <<'PY'
import collections, json, sys
manifest, tag, binary = sys.argv[1:]
M = json.load(open(manifest))
for side in ("current", "assumed"):
    try:
        d = json.load(open(f"/root/tdo_compare/{tag}.{side}.json"))
    except Exception as error:
        print(tag, side, "FAILED", error); continue
    t = collections.Counter(); bad = []
    for c in M["cases"]:
        if c["binary"] != binary or c["function"] not in d:
            continue
        anchor = f"{c['anchor']['callee']}.arg{c['anchor']['arg_index']}"
        roots = [r for r in d[c["function"]]["roots"] if r["label"] == anchor]
        origins = {o for r in roots for o in r["origins"]}
        missing = bool(set(c["expected_sources"]) - origins)
        extra = bool(set(c["forbidden_sources"]) & origins)
        sure = all(r.get("effective", r.get("complete")) for r in roots) if roots else False
        kind = "missing" if missing else ("extra-only" if extra else "exact")
        t[(kind, "sure" if sure else "unsure")] += 1
        if kind == "missing" and sure:
            bad.append(c["function"])
    label = "default" if side == "current" else "assumed(TEST-ONLY)"
    print(f"{tag:12} {label:19} cases={sum(t.values())} PASS(exact)={t[('exact','sure')] + t[('exact','unsure')]} "
          f"exact+sure={t[('exact','sure')]} "
          f"{dict(sorted(t.items()))} missing+sure={bad}")
PY
