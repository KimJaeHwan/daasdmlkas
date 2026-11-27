#!/bin/bash
# X-1b: stages 0 and 1 for the named pairs of /root/x1b_pairs.json (by Bundle name), one after another
C=$(cd "$(dirname "$0")" && pwd); TREE=$(cd "$C/../.." && pwd); PAIRS=${PAIRS:-/root/x1b_pairs.json}
for n in "$@"; do
  key=$(python3 -c "import json,sys; d=json.load(open('$PAIRS'))['pairs']; print([k for k,v in d.items() if v['name']==sys.argv[1]][0])" "$n")
  ~/venvs/tdo/bin/python $C/x1b_stages.py $TREE $PAIRS "$key" --jobs ${JOBS:-2} --configs ${CONFIGS:-default,legacy} ${COMPARE_ONLY:+--compare-only} 2>&1 | grep -E "STAGESDONE|FAILED|Error|Traceback"
done
echo ALLSTAGESDONE
