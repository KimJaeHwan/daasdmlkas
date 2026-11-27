#!/usr/bin/env bash
# G2b r2 measurement: per Bundle the order base, new, new, base (ABBA); outputs of the first base / new kept.
set -euo pipefail
C=/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6
PY=/root/venvs/tdo/bin/python
ZL=$(ls -d /root/tdo_bundles3/zlib/*/ | grep -v logs | head -1)
NT=$(ls -d /root/tdo_g2/ntdll/*/ | grep -v logs | head -1)
UE=$(ls -d /root/tdo_bundles3/ue-core-probe/*/ | grep -v logs | head -1)
V3=$(ls -d /root/tdo_bundles3/v3-win-release-full/*/ | grep -v logs | head -1)
CL=$(find /root/tdo_bundles4/corpus/clang-x64-O0 -maxdepth 2 -name seal.json | head -1 | xargs dirname)
ulimit -v 14000000
for spec in "zlib:$ZL:src" "clang:$CL:/root/g1_runs/main_src_1828683/src" "v3:$V3:src" "ntdll:$NT:src" "ue_probe:$UE:src"; do
  name=${spec%%:*}; rest=${spec#*:}; G=${rest%%:*}; P0=${rest#*:}
  n=0
  for side in base new new base; do
    n=$((n + 1))
    WT=$C/wt_lint; [ $side = base ] && WT=$C/wt_g2b_base
    P=$P0; [ "$P" = src ] && P=$WT/src
    OUT=/root/g1_runs/g2b_r2_${side}_$n; mkdir -p $OUT
    [ $n -le 2 ] && OUT=/root/g1_runs/g2b_r2_$side && mkdir -p $OUT
    rm -f $OUT/$name.json $OUT/$name.evidence5.json $OUT/$name.facts.json
    echo "== $side#$n $name $(date +%T)"
    cd $WT
    /usr/bin/time -f "TIME $side#$n $name %e s %M KB" env PYTHONPATH=$P PYTHONHASHSEED=0 $PY tools/decode_check/decode_check.py "$G" \
      --out $OUT/$name.json --assume-stock-ghidra-translator \
      --evidence-out $OUT/$name.evidence5.json --common-facts $OUT/$name.facts.json > $OUT/$name.log 2>&1 || { tail -5 $OUT/$name.log; exit 1; }
    tail -1 $OUT/$name.log
  done
done
echo "ABBA DONE $(date +%T)"
