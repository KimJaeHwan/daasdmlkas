#!/usr/bin/env bash
# Program-oracle results of two gates, side by side: every config whose line differs (old line, then new), and
# every config missing on either side. Exit status: 0 all identical, 1 a difference or a missing result.
# usage: tools/gate/oracle_compare.sh <old label> <new label>   (logs under $TDO_LOGS: tools/gate/env.sh)
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
A=$TDO_LOGS/gate_par_${1:?old label}; B=$TDO_LOGS/gate_par_${2:?new label}
n=0; bad=0
for name in $( (cd "$A" 2>/dev/null && ls oracle.*.out; cd "$B" 2>/dev/null && ls oracle.*.out) | sort -u); do
  if [ ! -f "$A/$name" ]; then echo "MISSING-OLD $name"; bad=1; continue; fi
  if [ ! -f "$B/$name" ]; then echo "MISSING-NEW $name"; bad=1; continue; fi
  if ! diff -q "$A/$name" "$B/$name" > /dev/null; then echo "DIFF $name"; cut -c1-260 "$A/$name"; cut -c1-260 "$B/$name"; bad=1; fi
  n=$((n+1))
done
echo "compared $n (a full gate has 26)"
[ $n = 26 ] || bad=1
exit $bad
