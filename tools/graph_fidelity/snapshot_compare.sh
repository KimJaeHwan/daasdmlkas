#!/usr/bin/env bash
# A-5: snapshots of the working tree (label $2, written to a fresh directory) compared with a
# baseline (label $1), every run of snapshot_expected.txt (snapshot_gate.py).
# Exits with the gate's status: 0 identical, 1 a result differs, 2 the gate is incomplete.
set -o pipefail
cd /mnt/d/01_gitproject/14_TDO_v2/daasdmlkas || exit 2
export PYTHONPATH=src
label='^[A-Za-z0-9][A-Za-z0-9._-]*$'   # (a plain directory name: never "." or "..")
if [[ ! "${1:-}" =~ $label || ! "${2:-}" =~ $label || "$1" == "$2" ]]; then
  echo "usage: snapshot_compare.sh <baseline label> <new label> (two different plain labels)"; exit 2
fi
A=/root/tdo_snapshots/$1; B=/root/tdo_snapshots/$2
[ -d "$A" ] || { echo "no baseline $A"; exit 2; }
# fresh: no artifact or status of an earlier run under this label can pass for this one
rm -rf "$B" || { echo "cannot remove $B"; exit 2; }
[ -e "$B" ] && { echo "$B still exists"; exit 2; }
mkdir -p "$B" || { echo "cannot create $B"; exit 2; }
# (the generators' own output kept with the snapshot: a harness failure shows as NOT RUN in the gate)
bash tools/graph_fidelity/snapshot_baseline.sh "$2" > "$B/generate.log" 2>&1
bash tools/graph_fidelity/snapshot_fixtures.sh "$2" >> "$B/generate.log" 2>&1
echo "== timing (fixtures)"; paste <(cut -d' ' -f1-4 "$A/fixtures.txt") <(cut -d' ' -f3-4 "$B/fixtures.txt")
~/venvs/tdo/bin/python tools/graph_fidelity/snapshot_gate.py "$A" "$B"
