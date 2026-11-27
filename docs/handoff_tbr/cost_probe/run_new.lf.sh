#!/usr/bin/env bash
# New (-5) runs on one Bundle; CROSS=1 turns on the E1 crosscheck switch. usage: run_new.lf.sh <name> <bundle>
# (impl r1: stale outputs removed first; any failure exits non-zero; the crosscheck line required with CROSS=1)
set -euo pipefail
WT=/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint
PY=/root/venvs/tdo/bin/python
OUT=/root/g1_runs/cost_new
mkdir -p $OUT
cd "$WT"
ulimit -v 14000000
name=$1; G=$2
rm -f $OUT/$name.json $OUT/$name.evidence5.json $OUT/$name.facts.json
echo "== $name $G cross=${CROSS:-0} $(date +%T)"
LOG=$(mktemp)
if ! /usr/bin/time -f '%e s %M KB' env PYTHONPATH=src PYTHONHASHSEED=0 TDO_V2_G2A_COST_CROSSCHECK=${CROSS:-0} \
    $PY tools/decode_check/decode_check.py "$G" \
    --out $OUT/$name.json --assume-stock-ghidra-translator \
    --evidence-out $OUT/$name.evidence5.json --common-facts $OUT/$name.facts.json > $LOG 2>&1; then
  tail -5 $LOG; echo "RESULT FAIL (decode_check failed)"; exit 1
fi
tail -2 $LOG
if [ "${CROSS:-0}" = 1 ] && ! grep -q "crosscheck passed for" $LOG; then echo "RESULT FAIL (no crosscheck line)"; exit 1; fi
ls -l $OUT/$name.json $OUT/$name.evidence5.json $OUT/$name.facts.json | awk '{print $5, $9}'
$PY -I -c "import json; h=json.load(open('$OUT/$name.json'))['header']['common_facts']; print('vendor_rows', h['vendor_rows'])"
$PY -I /mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/cost_probe/equiv.py "$WT" /root/g1_runs/oracle798 $OUT $name
