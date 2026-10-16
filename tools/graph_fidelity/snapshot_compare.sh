#!/usr/bin/env bash
# A-5: snapshots of the working tree (label $2) compared with a baseline (label $1), every artifact.
set -o pipefail
cd /mnt/d/01_gitproject/14_TDO_v2/daasdmlkas
export PYTHONPATH=src
bash tools/graph_fidelity/snapshot_baseline.sh $2 > /dev/null 2>&1
bash tools/graph_fidelity/snapshot_fixtures.sh $2 > /dev/null 2>&1
A=/root/tdo_snapshots/$1; B=/root/tdo_snapshots/$2
status=0
for f in $A/*.json.gz; do
  name=$(basename $f)
  if [ ! -f $B/$name ]; then echo "MISSING $name"; status=2; continue; fi
  ~/venvs/tdo/bin/python tools/graph_fidelity/semantic_snapshot.py compare $f $B/$name | tail -3 | sed "s/^/$name: /" || status=1
done
echo "== baseline failures (must be the same)"; grep -v "rc=0" $A/status.txt | cut -c1-120; echo "== now"; grep -v "rc=0" $B/status.txt | cut -c1-120
echo "== timing (fixtures)"; paste <(cut -d' ' -f1-4 $A/fixtures.txt) <(cut -d' ' -f3-4 $B/fixtures.txt)
echo "COMPAREDONE status=$status"
