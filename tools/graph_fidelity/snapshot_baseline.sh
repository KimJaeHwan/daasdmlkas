#!/usr/bin/env bash
# A-5 phase 0: semantic snapshots of every Bundle and configuration (one process each, with timeouts).
# usage: snapshot_baseline.sh <label>   -> $TDO_SNAPSHOTS/<label>/*.json.gz, status.txt
#   (paths, python and the tree under test: tools/gate/env.sh)
set -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../gate/env.sh"
cd "$TDO_REPO" || exit 2
export PYTHONPATH=src
OUT=$TDO_SNAPSHOTS/$1; mkdir -p "$OUT"; : > "$OUT"/status.txt
snap() {   # name generation config [binding]
  local extra=""; [ -n "${4:-}" ] && extra="--binding $4"
  "$PY" -I "$TDO_GATE_DIR/timed.py" --out "$OUT/$1.$3.time" --timeout ${TIMEOUT:-3000} -- "$PY" tools/graph_fidelity/semantic_snapshot.py dump "$2" "$OUT/$1.$3.json.gz" --config $3 $extra > "$OUT/$1.$3.log" 2>&1
  local rc=$?
  echo "$1.$3 rc=$rc timeout=${TIMEOUT:-3000} $(tail -1 $OUT/$1.$3.log | cut -c1-160)" >> $OUT/status.txt
}
for b in v2-win-debug-full v3-win-release-full v3-win32-release-full zlib ue-dll-debuggame ue-dll-development; do
  G=$(ls -d "$TDO_BUNDLES"/$b/*/ | head -1)
  snap $b $G default; snap $b $G off
done
for b in debuggame development; do
  G=$(ls -d "$TDO_BUNDLES"/ue-dll-$b/*/ | head -1)
  snap ue-dll-$b $G accessor models/bindings/tv2_unreal_$b.json
done
for c in clang-x64-O0 clang-x64-O2 clang-x64-O3 clang-x86-O0 clang-x86-O2 gcc-x64-O2-rep gcc-x64-O3; do
  G=$(ls -d "$TDO_BUNDLES"/corpus/$c/*/ | head -1)
  snap corpus-$c $G default
done
TIMEOUT=1200
for b in v2-win-debug-full v3-win-release-full; do
  G=$(ls -d "$TDO_BUNDLES"/$b/*/ | head -1); snap $b $G legacy
done
for c in clang-x64-O0 clang-x64-O2 gcc-x64-O3; do
  G=$(ls -d "$TDO_BUNDLES"/corpus/$c/*/ | head -1); snap corpus-$c $G legacy
done
cat $OUT/status.txt
echo SNAPDONE
