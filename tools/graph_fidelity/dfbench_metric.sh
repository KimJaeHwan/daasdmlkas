#!/usr/bin/env bash
# DataFlowBench-style case metric for one Bundle generation, default and
# TEST-ONLY assumed-boundary modes. Run in WSL.
# usage: dfbench_metric.sh <generation> <tag> [binary] [manifest]
#   default manifest: 09 cases_manifest.json. 10 UE manifests (cases_v2_manifest.json:
#   expected_data_sources + expected_global_sources, forbidden_data_sources) also work.
# Prints, per mode, counts of (exact|missing|extra-only, sure|unsure) and the
# cases whose function is not in the Bundle; "missing + sure" must stay 0.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
G=$1; TAG=$2; BIN=${3:-dfbench_win_core}
M=${4:-/mnt/d/01_gitproject/09_tdo_testbed/manifests/cases_manifest.json}
# Each run is capped by METRIC_TIMEOUT seconds (default 1200): the
# interprocedural layer can hang (win32 MSVC, UE DLLs). A timed-out mode prints FAILED.
mkdir -p /root/tdo_compare
rm -f "/root/tdo_compare/$TAG.current.json" "/root/tdo_compare/$TAG.assumed.json"
cd "$REPO"
timeout "${METRIC_TIMEOUT:-1200}" ~/venvs/tdo/bin/python tools/bundle_export/run_dfbench.py "$G" \
    --json "/root/tdo_compare/$TAG.current.json" > "/root/tdo_compare/$TAG.current.log" 2>&1
timeout "${METRIC_TIMEOUT:-1200}" ~/venvs/tdo/bin/python tools/bundle_export/run_dfbench.py "$G" --assume-boundary-effects \
    --json "/root/tdo_compare/$TAG.assumed.json" > "/root/tdo_compare/$TAG.assumed.log" 2>&1
python3 - "$M" "$TAG" "$BIN" <<'PY'
import collections, json, sys
manifest, tag, binary = sys.argv[1:]
M = json.load(open(manifest, encoding="utf-8"))
for side in ("current", "assumed"):
    try:
        d = json.load(open(f"/root/tdo_compare/{tag}.{side}.json"))
    except Exception as error:
        print(tag, side, "FAILED", error); continue
    t = collections.Counter(); bad = []; absent = []
    for c in M["cases"]:
        if c["binary"] != binary:
            continue
        if c["function"] not in d:
            absent.append(c["function"]); continue
        want = c.get("expected_sources",
                     c.get("expected_data_sources", []) + c.get("expected_global_sources", []))
        forbid = c.get("forbidden_sources", c.get("forbidden_data_sources", []))
        anchor = f"{c['anchor']['callee']}.arg{c['anchor']['arg_index']}"
        roots = [r for r in d[c["function"]]["roots"] if r["label"] == anchor]
        origins = {o for r in roots for o in r["origins"]}
        missing = bool(set(want) - origins)
        extra = bool(set(forbid) & origins)
        sure = all(r.get("effective", r.get("complete")) for r in roots) if roots else False
        kind = "missing" if missing else ("extra-only" if extra else "exact")
        t[(kind, "sure" if sure else "unsure")] += 1
        if kind == "missing" and sure:
            bad.append(c["function"])
    label = "default" if side == "current" else "assumed(TEST-ONLY)"
    print(f"{tag:12} {label:19} cases={sum(t.values())} PASS(exact)={t[('exact','sure')] + t[('exact','unsure')]} "
          f"exact+sure={t[('exact','sure')]} "
          f"{dict(sorted(t.items()))} missing+sure={bad} absent={len(absent)}")
    total = sum(t.values()) + len(absent)
    exact = t[('exact', 'sure')] + t[('exact', 'unsure')]
    extra = t[('extra-only', 'sure')] + t[('extra-only', 'unsure')]
    missing = t[('missing', 'sure')] + t[('missing', 'unsure')]
    pct = lambda n: f"{100 * n / total:.0f}%" if total else "-"
    print(f"{'':12} {label:19} SUMMARY of {total} cases: exact {exact} ({pct(exact)}) | "
          f"exact+sure {t[('exact','sure')]} ({pct(t[('exact','sure')])}) | over-reported {extra} | "
          f"missing {missing} (sure {len(bad)}) | not in Bundle {len(absent)}")
PY
