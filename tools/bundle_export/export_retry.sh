#!/usr/bin/env bash
# Export with --functions-from-manifest, dropping names Ghidra cannot find
# (inlined / folded in optimized builds) until the export succeeds.
# usage: export_retry.sh <binary> <output-root> [extra export args...]
set -u
BIN=$1; OUT=$2; shift 2
REPO=$(cd "$(dirname "$0")/../.." && pwd)
MANIFEST=/mnt/d/01_gitproject/09_tdo_testbed/manifests/cases_manifest.json
EXCLUDE=()
for attempt in $(seq 1 60); do
  LOG=$(python3 "$REPO/tools/bundle_export/export_bundle.py" "$BIN" --functions-from-manifest "$MANIFEST" \
        "$@" "${EXCLUDE[@]}" --output-root "$OUT" 2>&1)
  if echo "$LOG" | grep -q '^\[export\] published'; then
    echo "$LOG" | grep '^\[export\]'; echo "excluded ${#EXCLUDE[@]} args: ${EXCLUDE[*]}"; exit 0
  fi
  SCRIPT_LOG=$(echo "$LOG" | grep -o '/root[^ ]*script.log' | tail -1)
  GHIDRA_LOG=${SCRIPT_LOG%script.log}ghidra.log
  NAME=$(grep -o 'missing or ambiguous: [A-Za-z0-9_]*' "$GHIDRA_LOG" | tail -1 | awk '{print $NF}')
  if [ -z "$NAME" ]; then echo "$LOG" | tail -5; echo "unrecoverable"; exit 1; fi
  EXCLUDE+=(--exclude-function "$NAME")
done
echo "gave up"; exit 1
