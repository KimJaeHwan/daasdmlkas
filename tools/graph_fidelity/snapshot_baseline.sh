#!/usr/bin/env bash
# A-5 phase 0: semantic snapshots of every Bundle and configuration (one process each, with timeouts).
# usage: snapshot_baseline.sh <label>   -> /root/tdo_snapshots/<label>/*.json.gz, status.txt
set -o pipefail
cd /mnt/d/01_gitproject/14_TDO_v2/daasdmlkas
export PYTHONPATH=src
OUT=/root/tdo_snapshots/$1; mkdir -p $OUT; : > $OUT/status.txt
snap() {   # name generation config [binding]
  local extra=""; [ -n "${4:-}" ] && extra="--binding $4"
  timeout ${TIMEOUT:-3000} ~/venvs/tdo/bin/python tools/graph_fidelity/semantic_snapshot.py dump "$2" "$OUT/$1.$3.json.gz" --config $3 $extra > "$OUT/$1.$3.log" 2>&1
  local rc=$?
  echo "$1.$3 rc=$rc $(tail -1 $OUT/$1.$3.log | cut -c1-160)" >> $OUT/status.txt
}
for b in v2-win-debug-full v3-win-release-full v3-win32-release-full zlib ue-dll-debuggame ue-dll-development; do
  G=$(ls -d /root/tdo_bundles3/$b/*/ | head -1)
  snap $b $G default; snap $b $G off
done
for b in debuggame development; do
  G=$(ls -d /root/tdo_bundles3/ue-dll-$b/*/ | head -1)
  snap ue-dll-$b $G accessor models/bindings/tv2_unreal_$b.json
done
for c in clang-x64-O0 clang-x64-O2 clang-x64-O3 clang-x86-O0 clang-x86-O2 gcc-x64-O2-rep gcc-x64-O3; do
  G=$(ls -d /root/tdo_bundles3/corpus/$c/*/ | head -1)
  snap corpus-$c $G default
done
TIMEOUT=1200
for b in v2-win-debug-full v3-win-release-full; do
  G=$(ls -d /root/tdo_bundles3/$b/*/ | head -1); snap $b $G legacy
done
for c in clang-x64-O0 clang-x64-O2 gcc-x64-O3; do
  G=$(ls -d /root/tdo_bundles3/corpus/$c/*/ | head -1); snap corpus-$c $G legacy
done
cat $OUT/status.txt
echo SNAPDONE
