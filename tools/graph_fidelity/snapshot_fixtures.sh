#!/usr/bin/env bash
# A-5 phase 0: fixture snapshots (one process each, timeout, peak memory).
# usage: snapshot_fixtures.sh <label>   -> $TDO_SNAPSHOTS/<label>/fixture-*.json.gz, fixtures.txt
#   (paths, python and the tree under test: tools/gate/env.sh)
set -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../gate/env.sh"
cd "$TDO_REPO" || exit 2
export PYTHONPATH=src
OUT=$TDO_SNAPSHOTS/$1; mkdir -p "$OUT"; : > "$OUT"/fixtures.txt
for name in chain-1k chain-5k chain-in-loop-600 loop-mixed-spans-40 diamonds-12 diamonds-30 wide-6k pointer-accesses-300 stack-spills-200 chain-8k; do
  timed $OUT/fixture-$name.time ${TIMEOUT:-900} "$PY" tools/graph_fidelity/fixture_snapshot.py $name $OUT/fixture-$name.json.gz > $OUT/fixture-$name.log 2>&1
  rc=$?
  echo "$name rc=$rc $(cat $OUT/fixture-$name.time 2>/dev/null | tail -1) $(tail -1 $OUT/fixture-$name.log | cut -c1-140) timeout=${TIMEOUT:-900}" >> $OUT/fixtures.txt
done
cat $OUT/fixtures.txt
echo FIXDONE
