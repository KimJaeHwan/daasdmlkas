# Gate paths and tools (sourced by the gate scripts). Each may be set in the environment; the defaults are the
# WSL layout of the development PC (data under root's home). On another machine (macOS: docs/mac_setup.md) set
# TDO_DATA to the unpacked data package and TDO_PY to the venv's python.
#   TDO_REPO       the tree under test (also REPO, the older name)   default: this checkout
#   TDO_DATA       data root                                          default: $HOME
#   TDO_BUNDLES    frozen Bundles (gate set)                          default: $TDO_DATA/tdo_bundles3
#   TDO_SNAPSHOTS  snapshot directories, one per label                default: $TDO_DATA/tdo_snapshots
#   TDO_LOGS       gate logs ($TDO_LOGS/gate_par_<label>)             default: $TDO_DATA
#   TDO_EVIDENCE   stack-switch evidence (core.stack.json)            default: $TDO_DATA/ghidra_link_evidence
#   TDO_PY         python of the project venv                         default: $HOME/venvs/tdo/bin/python
TDO_GATE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TDO_REPO=${TDO_REPO:-${REPO:-$(cd "$TDO_GATE_DIR/../.." && pwd)}}
TDO_DATA=${TDO_DATA:-$HOME}
TDO_BUNDLES=${TDO_BUNDLES:-$TDO_DATA/tdo_bundles3}
TDO_SNAPSHOTS=${TDO_SNAPSHOTS:-$TDO_DATA/tdo_snapshots}
TDO_LOGS=${TDO_LOGS:-$TDO_DATA}
TDO_EVIDENCE=${TDO_EVIDENCE:-$TDO_DATA/ghidra_link_evidence}
TDO_PY=${TDO_PY:-$HOME/venvs/tdo/bin/python}
PY=$TDO_PY
# (paths go through whitespace-separated job lists: no blanks in them)
for name in TDO_GATE_DIR TDO_REPO TDO_DATA TDO_BUNDLES TDO_SNAPSHOTS TDO_LOGS TDO_EVIDENCE TDO_PY; do
  case "${!name}" in *[[:space:]]*) echo "gate: $name has a blank in it (${!name}): not supported"; exit 2;; esac
done
export TDO_GATE_DIR TDO_REPO TDO_DATA TDO_BUNDLES TDO_SNAPSHOTS TDO_LOGS TDO_EVIDENCE TDO_PY PY

# timed OUT LIMIT cmd...: wall time and peak memory to OUT ("%e s %M KB"), LIMIT seconds (0: none); exit 124 on
# time-out (GNU time + timeout, portable: tools/gate/timed.py)
timed() {
  local out=$1 limit=$2; shift 2
  if [ "$limit" = 0 ]; then "$PY" -I "$TDO_GATE_DIR/timed.py" --out "$out" -- "$@"
  else "$PY" -I "$TDO_GATE_DIR/timed.py" --out "$out" --timeout "$limit" -- "$@"; fi
}
export -f timed
[ -x "$PY" ] || { echo "gate: no python at $PY (set TDO_PY)"; exit 2; }
