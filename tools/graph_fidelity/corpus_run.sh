#!/usr/bin/env bash
# Export every built corpus variant (tests/corpus/intra/build/*) to a Bundle and
# run the graph-fidelity measurement on it. Run in WSL.
# usage: corpus_run.sh [runs] [--measure-only]   (--measure-only reuses existing Bundles)
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
RUNS=${1:-6}
MEASURE_ONLY=${2:-}
NAMES=$(grep -o 'EXPORT [a-z_0-9 *]* \([a-z_0-9]*\)(' "$REPO/tests/corpus/intra/intra_corpus.c" \
        | sed 's/.* \**\([a-z_0-9]*\)($/\1/' | sort -u | sed 's/^/--function-name /' | tr '\n' ' ')
for dir in "$REPO"/tests/corpus/intra/build/*/; do
  variant=$(basename "$dir")
  binary=$(ls "$dir" | head -1)
  out=/root/tdo_bundles/corpus/$variant
  if [ "$MEASURE_ONLY" != "--measure-only" ]; then
    rm -rf "$out"
    python3 "$REPO/tools/bundle_export/export_bundle.py" "$dir$binary" $NAMES --output-root "$out" \
        > "/tmp/corpus-$variant.export.log" 2>&1
  fi
  gen=$(ls -d "$out"/*/ 2>/dev/null | head -1)
  if [ -z "$gen" ]; then echo "$variant: EXPORT FAILED (see /tmp/corpus-$variant.export.log)"; continue; fi
  ~/venvs/tdo/bin/python "$REPO/tools/graph_fidelity/measure_bundle.py" "$gen" --runs "$RUNS" \
      --json "/tmp/corpus-$variant.json" > "/tmp/corpus-$variant.out" 2>&1
  python3 - "$variant" "/tmp/corpus-$variant.json" <<'PY'
import json, sys
variant, path = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(path))["summary"]
except Exception as error:
    print(variant, "MEASURE FAILED", error); sys.exit()
t = d["totals"]
print(f"{variant:16} lang={d['language']:22} fns={t.get('functions')} checked={t.get('checked')} "
      f"missing={t.get('missing')} unexplained={t.get('unexplained')} control={t.get('control_violations')} "
      f"skipped={t.get('skipped_runs')} failures={d['normalize_failures']} skip_reasons={d['skipped_run_reasons']} "
      f"opaque={sorted(d['opaque_opcodes'])} max_ins={d['size']['max']} iter_err={t.get('stopped_by_iterator_error', 0)}")
PY
done
