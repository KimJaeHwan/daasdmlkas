#!/usr/bin/env bash
# Cost check on the mac: per Bundle base (c15a29a, wt_g2b_base), new (wt_lint), new, base. Compare ratios only.
# Outputs of the first base / new go to $DATA/g1_runs/mac_base and mac_new for cost_probe/equiv_g2b.py.
# usage: bash run_abba_mac.sh [names...]   (default: zlib clang v3 ntdll ue_probe)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
names=${*:-zlib clang v3 ntdll ue_probe}
for name in $names; do
  case $name in
    zlib) G=$ZL ;; clang) G=$CL ;; v3) G=$V3 ;; ntdll) G=$NT ;; ue_probe) G=$UE ;;
  esac
  n=0
  for side in base new new base; do
    n=$((n + 1))
    WT=$C/wt_lint; [ $side = base ] && WT=$C/wt_g2b_base
    P=$WT/src; [ $name = clang ] && P=$CLANG_SRC
    OUT=$DATA/g1_runs/mac_${side}_$n; [ $n -le 2 ] && OUT=$DATA/g1_runs/mac_$side
    mkdir -p "$OUT"
    rm -f "$OUT/$name.json" "$OUT/$name.evidence5.json" "$OUT/$name.facts.json"
    cd "$WT"
    PYTHONPATH=$P "$PY" "$HERE/timed.py" "$side#$n $name" "$OUT/$name.log" -- "$PY" tools/decode_check/decode_check.py "$G" \
        --out "$OUT/$name.json" --assume-stock-ghidra-translator \
        --evidence-out "$OUT/$name.evidence5.json" --common-facts "$OUT/$name.facts.json"
  done
  "$PY" "$C/wt_lint/docs/handoff_tbr/cost_probe/equiv_g2b.py" "$DATA/g1_runs/mac_base" "$DATA/g1_runs/mac_new" "$name" \
      | grep -E "FAIL|RESULT|FACTS_BYTES"
done
