#!/usr/bin/env bash
# A-5 phase 0: fixture snapshots (one process each, timeout, peak memory).
# usage: snapshot_fixtures.sh <label>   -> /root/tdo_snapshots/<label>/fixture-*.json.gz, fixtures.txt
set -o pipefail
cd /mnt/d/01_gitproject/14_TDO_v2/daasdmlkas
export PYTHONPATH=src
OUT=/root/tdo_snapshots/$1; mkdir -p $OUT; : > $OUT/fixtures.txt
for name in chain-1k chain-5k chain-in-loop-600 loop-mixed-spans-40 diamonds-12 diamonds-30 wide-6k pointer-accesses-300 stack-spills-200 chain-8k; do
  /usr/bin/time -f "%e s %M KB" -o $OUT/fixture-$name.time timeout ${TIMEOUT:-900} ~/venvs/tdo/bin/python tools/graph_fidelity/fixture_snapshot.py $name $OUT/fixture-$name.json.gz > $OUT/fixture-$name.log 2>&1
  rc=$?
  echo "$name rc=$rc $(cat $OUT/fixture-$name.time 2>/dev/null | tail -1) $(tail -1 $OUT/fixture-$name.log | cut -c1-140) timeout=${TIMEOUT:-900}" >> $OUT/fixtures.txt
done
cat $OUT/fixtures.txt
echo FIXDONE
