#!/usr/bin/env bash
# G2b runs: usage run_g2b.lf.sh <tag> <name:bundle> ...; prints time / peak, file sizes and the code summary.
set -euo pipefail
WT=/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint
PY=/root/venvs/tdo/bin/python
TAG=$1; shift
OUT=/root/g1_runs/g2b_$TAG
mkdir -p $OUT
cd "$WT"
ulimit -v 14000000
for spec in "$@"; do
  name=${spec%%:*}; rest=${spec#*:}; G=${rest%%:*}; P=${rest#*:}; [ "$P" = "$rest" ] && P=src
  rm -f $OUT/$name.json $OUT/$name.evidence5.json $OUT/$name.facts.json
  echo "== $name $(date +%T)"
  LOG=$(mktemp)
  if ! /usr/bin/time -f '%e s %M KB' env PYTHONPATH=$P PYTHONHASHSEED=0 $PY tools/decode_check/decode_check.py "$G" \
      --out $OUT/$name.json --assume-stock-ghidra-translator \
      --evidence-out $OUT/$name.evidence5.json --common-facts $OUT/$name.facts.json > $LOG 2>&1; then
    tail -8 $LOG; echo "FAIL $name"; exit 1
  fi
  tail -1 $LOG
  ls -l $OUT/$name.facts.json $OUT/$name.evidence5.json $OUT/$name.json | awk '{print $5, $9}'
  $PY -I -c "
import json
h = json.load(open('$OUT/$name.json'))['header']['common_facts']['code']
print(json.dumps({k: h[k] for k in ('sites', 'trap_forms', 'unresolved', 'unsupported', 'rows_outside_code', 'verified_encoding')}))
print('regions', len(h['regions']), 'verified bytes', sum(r['verified_bytes'] for r in h['regions']))
"
done
