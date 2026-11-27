#!/usr/bin/env bash
# Run 7a3cefe (the pushed feat/g1-decode-check head) on this machine and compare with the office outputs of the
# same code ($DATA/g1_runs/g2b_r2_new). Expected: facts files byte-identical, -5 blocks identical, reports and
# evidence identical except the decoder build digests and output paths.
# usage: bash parity_mac.sh [names...]   (default: zlib clang v3 ntdll ue_probe; ue_probe takes the longest)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
WT=$C/wt_parity
[ -d "$WT" ] || git -C "$REPO" worktree add --detach "$WT" 7a3cefe
OUT=$DATA/g1_runs/mac_parity; mkdir -p "$OUT"
names=${*:-zlib clang v3 ntdll ue_probe}
for name in $names; do
  case $name in
    zlib) G=$ZL; P=$WT/src ;; clang) G=$CL; P=$CLANG_SRC ;; v3) G=$V3; P=$WT/src ;;
    ntdll) G=$NT; P=$WT/src ;; ue_probe) G=$UE; P=$WT/src ;;
  esac
  cd "$WT"
  PYTHONPATH=$P "$PY" "$HERE/timed.py" "mac $name" "$OUT/$name.log" -- "$PY" tools/decode_check/decode_check.py "$G" \
      --out "$OUT/$name.json" --assume-stock-ghidra-translator \
      --evidence-out "$OUT/$name.evidence5.json" --common-facts "$OUT/$name.facts.json"
  "$PY" "$HERE/parity_check.py" "$DATA/g1_runs/g2b_r2_new" "$OUT" "$name"
done
