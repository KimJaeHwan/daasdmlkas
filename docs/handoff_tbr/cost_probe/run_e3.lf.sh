#!/usr/bin/env bash
# E3 on one Bundle: oracle tree + oracle -4, new tree + new -5, new tree + oracle -4; the three digests must be equal
# and every reader must reject the same invalid document (Astra impl r1 item 1). usage: run_e3.lf.sh <name> <bundle>
set -euo pipefail
PY=/root/venvs/tdo/bin/python
C=/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6
ulimit -v 14000000
name=$1; G=$2
oracle_digest=''
for spec in "oracle-tree/-4:$C/wt_g2a_oracle:/root/g1_runs/oracle798/$name.evidence4.json:/root/g1_runs/oracle798/$name.facts.json" \
            "new-tree/-5:$C/wt_lint:/root/g1_runs/cost_new/$name.evidence5.json:/root/g1_runs/cost_new/$name.facts.json" \
            "new-tree/oracle-4:$C/wt_lint:/root/g1_runs/oracle798/$name.evidence4.json:/root/g1_runs/oracle798/$name.facts.json"; do
  IFS=: read -r label tree ev facts <<< "$spec"
  echo "== $label $(date +%T)"
  result=$(
    cd /root
    /usr/bin/time -f '%e s %M KB' env PYTHONHASHSEED=0 "$PY" -I "$C/cost_probe/e3_lookups.py" "$tree" "$G" "$ev" "$facts" 2>&1
  )
  printf '%s\n' "$result" | tail -4
  grep -q "rejects an invalid row aggregate" <<< "$result" || { echo "$label: no rejection" >&2; exit 1; }
  digest=$(awk '$1 == "DIGEST" {print $2}' <<< "$result")
  if [[ ! $digest =~ ^[0-9a-f]{64}$ ]]; then
    echo "$label: missing or malformed digest" >&2
    exit 1
  fi
  if [[ -z $oracle_digest ]]; then
    oracle_digest=$digest
  elif [[ $digest != "$oracle_digest" ]]; then
    echo "$label: $digest differs from oracle $oracle_digest" >&2
    exit 1
  fi
done
echo "E3 PASS $name $oracle_digest"
