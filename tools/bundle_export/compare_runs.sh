#!/usr/bin/env bash
# Run run_dfbench.py on the same bundles with a baseline tree and the working tree.
# usage: compare_runs.sh <baseline_src> <out_dir> <gen>:<binary> ...
set -u
BASE_SRC=$1; OUT=$2; shift 2
REPO=$(cd "$(dirname "$0")/../.." && pwd)
PY=~/venvs/tdo/bin/python
MANIFEST=/mnt/d/01_gitproject/09_tdo_testbed/manifests/cases_manifest.json
mkdir -p "$OUT"
for spec in "$@"; do
  gen=${spec%%:*}; bin=${spec##*:}; tag=$(basename "$gen" | cut -c1-8)
  for side in baseline current; do
    if [ $side = baseline ]; then export PYTHONPATH=$BASE_SRC; else unset PYTHONPATH; fi
    $PY "$REPO/tools/bundle_export/run_dfbench.py" "$gen" --expected "$MANIFEST" \
      --binary "$bin" --json "$OUT/$tag.$side.json" > "$OUT/$tag.$side.txt" 2>&1
    echo "$tag $side exit=$? $(grep '^\[run\]' "$OUT/$tag.$side.txt" | tr '\n' ' ')"
  done
done
