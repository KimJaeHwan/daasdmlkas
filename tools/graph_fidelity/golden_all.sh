#!/usr/bin/env bash
# Snapshot (dump) or compare normalization results for the whole verification
# set: corpus variants, 09 v2 Bundles and 10 UE Bundles (default + TEST-ONLY
# assumed), zlib. WSL.
# usage: [BUNDLE_ROOT=/root/tdo_bundles3] golden_all.sh dump <dir>
#        golden_all.sh compare <dir-a> <dir-b> [--terminal-runs-only]
set -u
set -o pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
PY=~/venvs/tdo/bin/python
TOOL="$REPO/tools/graph_fidelity/ssa_snapshot.py"
gen() { ls -d "$1"/*/ 2>/dev/null | head -1; }
SETS=()
for dir in ${BUNDLE_ROOT:-/root/tdo_bundles}/corpus/*/; do case $dir in *.logs/) continue;; esac; SETS+=("corpus-$(basename "$dir")|$(gen "$dir")|"); done
for name in v2-win-release v2-win-debug-subset v2-win32-release; do
  SETS+=("$name|$(gen ${BUNDLE_ROOT:-/root/tdo_bundles}/$name)|" "$name-assumed|$(gen ${BUNDLE_ROOT:-/root/tdo_bundles}/$name)|--assume-boundary-effects")
done
SETS+=("zlib|$(gen ${BUNDLE_ROOT:-/root/tdo_bundles}/zlib)|")
for name in ue-cpp-P0-x64 ue-cpp-P1-x64 ue-cpp-P0-x86 ue-cpp-P1-x86 ue-dll-development ue-dll-debuggame; do
  SETS+=("$name|$(gen ${BUNDLE_ROOT:-/root/tdo_bundles}/$name)|" "$name-assumed|$(gen ${BUNDLE_ROOT:-/root/tdo_bundles}/$name)|--assume-boundary-effects")
done
cmd=$1; shift
status=0
for item in "${SETS[@]}"; do
  IFS='|' read -r tag generation flag <<< "$item"
  if [ "$cmd" = dump ]; then
    mkdir -p "$1"
    # (a failed or timed-out dump fails the run: it is not a passing snapshot)
    timeout 1800 $PY "$TOOL" dump "$generation" "$1/$tag.json.gz" $flag 2>/dev/null | sed "s/^/$tag: /" \
      || { echo "$tag: DUMP FAILED (rc=$?)"; status=2; }
  else
    echo "== $tag"; $PY "$TOOL" compare "$1/$tag.json.gz" "$2/$tag.json.gz" ${3:-} | tail -4 || status=1
  fi
done
exit $status
