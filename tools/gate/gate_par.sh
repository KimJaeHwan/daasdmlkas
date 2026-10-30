#!/usr/bin/env bash
# Parallel gate: suites forward 0/1, snapshot compare vs a baseline, program oracle 13 configs x forward 0/1,
# the shipped UE template re-derived -- run concurrently. Each job's time and peak memory go to $LOG/*.time.
# usage: tools/gate/gate_par.sh <baseline label> <new label>
#   paths / python: tools/gate/env.sh (TDO_DATA, TDO_PY, TDO_REPO ...)
#   env: SUITE_WORKERS (7 per mode), SNAP_JOBS (4), ORACLE_JOBS (6), STOP_AFTER=snapshot (no oracle)
# Compare two gates' oracle results: tools/gate/oracle_compare.sh <old label> <new label>.
# Exit status: 0 when every check passed (suites, snapshot gate verdict, UE template, every oracle config ran),
# 1 otherwise; the last line names the failed checks (GATE RESULT). Ctrl-C / SIGTERM stop every job.
set -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "$TDO_REPO" || exit 2
BASE=${1:?baseline label}; NEW=${2:?new label}
label='^[A-Za-z0-9][A-Za-z0-9._-]*$'   # (a plain directory name: never "." or ".."; the baseline is never rewritten)
# (labels equal but for case name one directory on a case-insensitive volume: macOS)
if [[ ! "$BASE" =~ $label || ! "$NEW" =~ $label ||
      "$(echo "$BASE" | tr 'A-Z' 'a-z')" == "$(echo "$NEW" | tr 'A-Z' 'a-z')" ]]; then
  echo "usage: gate_par.sh <baseline label> <new label> (two different plain labels)"; exit 2
fi
SUITE_WORKERS=${SUITE_WORKERS:-7}; SNAP_JOBS=${SNAP_JOBS:-4}; ORACLE_JOBS=${ORACLE_JOBS:-6}
LOG=$TDO_LOGS/gate_par_$NEW; rm -rf "$LOG"; mkdir -p "$LOG"
exec > >(tee -a "$LOG/gate.log") 2>&1
T0=$(date +%s)
stamp() { echo "[$(( $(date +%s) - T0 ))s] $*"; }
FAILED=""
fail() { FAILED="$FAILED; $*"; echo "GATE FAILURE: $*"; }
finish() {   # the verdict line and exit status
  if [ -z "$FAILED" ]; then echo "GATE RESULT: PASS"; exit 0; fi
  echo "GATE RESULT: FAIL:${FAILED#;}"; exit 1
}
# stop: this gate's own process tree only, parents first (a timed.py wrapper hears it before its command, so
# it ends with SIGKILL to the command's group)
stop_tree() { local children child; children=$(pgrep -P "$1"); kill -TERM "$1" 2>/dev/null
              for child in $children; do stop_tree "$child"; done; }
trap 'trap - INT TERM; echo "gate stopped"; for c in $(pgrep -P $$); do stop_tree "$c"; done; exit 130' INT TERM
A=$TDO_SNAPSHOTS/$BASE; B=$TDO_SNAPSHOTS/$NEW
[ -d "$A" ] || { echo "no baseline $A"; exit 2; }
[ -e "$B" ] && [ "$A" -ef "$B" ] && { echo "$A and $B are one directory"; exit 2; }
rm -rf "$B"; mkdir -p "$B"
G() { ls -d "$TDO_BUNDLES/$1"/*/ | grep -v logs | head -1; }
export -f G
stamp "gate $NEW vs $BASE: tree $TDO_REPO ($(git rev-parse --short HEAD 2>/dev/null || echo "commit ?")), data $TDO_DATA, python $PY"

snap_one() {   # name bundle config binding(- none) timeout
  local name=$1 bundle=$2 config=$3 binding=$4 limit=$5 extra=""
  [ "$binding" != "-" ] && extra="--binding $binding"
  timed "$LOG/snap.$name.$config.time" "$limit" \
    "$PY" tools/graph_fidelity/semantic_snapshot.py dump "$bundle" "$B/$name.$config.json.gz" \
    --config $config $extra > "$B/$name.$config.log" 2>&1
  echo "$name.$config rc=$? timeout=$limit $(tail -1 "$B/$name.$config.log" | cut -c1-160)" > "$LOG/snap.$name.$config.status"
}
export -f snap_one; export LOG B

oracle_one() {
  set -o pipefail      # (an exported function runs in a fresh bash: shell options are not exported)
  local mode=$1 bundle=$2; shift 2
  local G=$(G "$bundle")
  local tag=$(echo "$mode $bundle $*" | sed 's/ *$//' | tr ' /' '__')
  TDO_V2_FORWARD=$mode timed "$LOG/oracle.$tag.time" 3000 \
    "$PY" tools/graph_fidelity/measure_program.py "$G" --runs 3 "$@" 2>&1 | grep '^{' | "$PY" -c '
import json, sys
d = json.loads(sys.stdin.read()); t = d["totals"]
print(sys.argv[1], {k: t.get(k, 0) for k in ("functions", "normalize_failures", "checked", "through_calls", "missing", "unexplained", "place_failed", "place_failed_debt", "forward_failures")}, [s for s in d["samples"]][:2])' "$(basename $bundle) $*" > "$LOG/oracle.$tag.out" \
    || { echo "$G $* ERROR" > "$LOG/oracle.$tag.out"; return 1; }
}
export -f oracle_one
# the oracle's long, light runs (zlib: ~17 min, ~0.7 GB each) start now, with the suites
EARLY_ORACLE="0 zlib|0 zlib --models|1 zlib --forward|1 zlib --models --forward"
early_oracle=()
IFS='|' read -ra early_jobs <<< "$EARLY_ORACLE"
if [ "${STOP_AFTER:-}" != snapshot ]; then
  for job in "${early_jobs[@]}"; do ( PYTHONPATH=src oracle_one $job ) & early_oracle+=($!); done
fi

# -- phase 1: both suites at once (xdist, work stealing); meanwhile the one
# long, light snapshot (v2 legacy: ~14 min, ~120 MB) ------------------------
stamp "SUITES (+ v2 legacy snapshot)"
( PYTHONPATH=src snap_one v2-win-debug-full "$(G v2-win-debug-full)" legacy - 2400 ) &   # (1200 sequentially; contention)
early=$!
# the shipped UE template re-derived with this tree (a stale template = a missed semantics bump)
( PYTHONPATH=src:tools/bundle_export timed "$LOG/uetemplate.time" 2400 \
    "$PY" "$TDO_GATE_DIR/check_ue_template.py" "$LOG/uetemplate.json" > "$LOG/uetemplate.out" 2>&1
  echo "uetemplate rc=$?" >> "$LOG/uetemplate.out" ) &
uetemplate=$!
# signal tests (Ctrl-C into the test process) cannot run in xdist workers
SERIAL="tests/intra/test_budgets.py tests/intra/test_resource_limits.py tests/intra/test_supervisor.py"
ignores=""; for f in $SERIAL; do ignores="$ignores --ignore=$f"; done
for mode in 0 1; do
  ( export TDO_V2_FORWARD=$mode PYTHONHASHSEED=0 PYTHONPATH=src:tests/intra
    timed "$LOG/suite_$mode.time" 0 \
      "$PY" -m pytest -q -p no:cacheprovider -n $SUITE_WORKERS --dist worksteal --durations=15 $ignores tests/ \
      --junitxml="$LOG/suite_$mode.xml" > "$LOG/suite_$mode.log" 2>&1
    echo $? > "$LOG/suite_$mode.rc"
    # (a background job starts with SIGINT ignored, so Python installs no
    # KeyboardInterrupt handler: restore it for the Ctrl-C tests)
    "$PY" -c 'import signal, sys, pytest; signal.signal(signal.SIGINT, signal.default_int_handler); sys.exit(pytest.main(sys.argv[1:]))' \
      -q -p no:cacheprovider $SERIAL --junitxml="$LOG/suite_serial_$mode.xml" \
      > "$LOG/suite_serial_$mode.log" 2>&1
    echo $? > "$LOG/suite_serial_$mode.rc" ) &
done
wait $(jobs -p | grep -v -x -e "$early" ${early_oracle[0]:+$(printf -- "-e %s " "${early_oracle[@]}")})
for mode in 0 1; do
  echo "SUITE FORWARD=$mode ($(cat "$LOG/suite_$mode.time"))"
  grep -E '^FAILED|^ERROR| passed| failed' "$LOG/suite_$mode.log" | tail -8
  grep -E '^FAILED|^ERROR| passed| failed' "$LOG/suite_serial_$mode.log" | tail -4 | sed 's/^/  serial: /'
  for part in suite suite_serial; do
    rc=$(cat "$LOG/${part}_$mode.rc" 2>/dev/null || echo none)
    [ "$rc" = 0 ] || fail "$part FORWARD=$mode rc=$rc"
  done
done

# -- phase 2: the other snapshots (longest first), then the gate ------------
stamp "SNAPSHOT"
export PYTHONPATH=src
jobs=$LOG/snap.jobs; : > "$jobs"
add() { echo "$1 $2 $3 ${4:--} ${5:-3000}" >> "$jobs"; }
for b in zlib ue-dll-debuggame ue-dll-development v2-win-debug-full v3-win-release-full v3-win32-release-full; do
  add $b "$(G $b)" default; add $b "$(G $b)" off
done
for b in debuggame development; do add ue-dll-$b "$(G ue-dll-$b)" accessor models/bindings/tv2_unreal_$b.json; done
add v3-win-release-full "$(G v3-win-release-full)" legacy - 1200
for c in clang-x64-O0 clang-x64-O2 clang-x64-O3 clang-x86-O0 clang-x86-O2 gcc-x64-O2-rep gcc-x64-O3; do
  add corpus-$c "$(G corpus/$c)" default
done
for c in clang-x64-O0 clang-x64-O2 gcc-x64-O3; do add corpus-$c "$(G corpus/$c)" legacy - 1200; done
xargs -P $SNAP_JOBS -L 1 "$BASH" -c 'snap_one "$0" "$1" "$2" "$3" "$4"' < "$jobs"
stamp "snapshots generated; waiting for v2 legacy"
wait $early
: > "$B/status.txt"
order="v2-win-debug-full.default v2-win-debug-full.off v3-win-release-full.default v3-win-release-full.off
v3-win32-release-full.default v3-win32-release-full.off zlib.default zlib.off ue-dll-debuggame.default
ue-dll-debuggame.off ue-dll-development.default ue-dll-development.off ue-dll-debuggame.accessor
ue-dll-development.accessor corpus-clang-x64-O0.default corpus-clang-x64-O2.default corpus-clang-x64-O3.default
corpus-clang-x86-O0.default corpus-clang-x86-O2.default corpus-gcc-x64-O2-rep.default corpus-gcc-x64-O3.default
v2-win-debug-full.legacy v3-win-release-full.legacy corpus-clang-x64-O0.legacy corpus-clang-x64-O2.legacy
corpus-gcc-x64-O3.legacy"
for item in $order; do cat "$LOG/snap.$item.status" >> "$B/status.txt" 2>/dev/null || echo "$item NOT RUN" >> "$B/status.txt"; done
# fixtures stay sequential and alone (their times are reported); the tree under test's code
bash "$TDO_GATE_DIR/../graph_fidelity/snapshot_fixtures.sh" "$NEW" > "$B/generate.log" 2>&1
"$PY" tools/graph_fidelity/snapshot_gate.py "$A" "$B" > "$LOG/snapshot.txt" 2>&1
snapshot_rc=$?
echo "snapshot gate rc=$snapshot_rc"
[ $snapshot_rc = 0 ] || fail "snapshot gate rc=$snapshot_rc (1: a result differs, 2: incomplete; see snapshot.txt)"
grep -E 'COMPAREDONE' "$LOG/snapshot.txt" | cut -c1-220
wait $uetemplate
grep -h -E "UETEMPLATE|uetemplate rc=" "$LOG/uetemplate.out" || { echo "UETEMPLATE ERROR"; tail -3 "$LOG/uetemplate.out"; }
grep -q "uetemplate rc=0" "$LOG/uetemplate.out" || fail "shipped UE template (see uetemplate.out)"
if [ "${STOP_AFTER:-}" = snapshot ]; then
  stamp "TIMES (s, peak KB)"
  for f in "$LOG"/*.time; do echo "$(basename $f .time) $(tail -1 $f)"; done | sort -k2 -n -r | head -12
  stamp "STOPPED AFTER SNAPSHOT"; finish
fi

# -- phase 3: program oracle -------------------------------------------------
stamp "PROGRAM-ORACLE"
ojobs=$LOG/oracle.jobs; : > "$ojobs"
line() { echo "$*" | sed 's/ *$//' >> "$ojobs"; }   # (no trailing blank: xargs -L would join lines)
for mode in 0 1; do
  extra=""; [ "$mode" = 1 ] && extra="--forward"
  for b in ue-dll-debuggame zlib v2-win-debug-full v3-win-release-full v3-win32-release-full ue-dll-development; do
    line $mode $b $extra; done
  for b in zlib v2-win-debug-full v3-win-release-full; do line $mode $b --models $extra; done
  for c in clang-x64-O0 clang-x64-O2 gcc-x64-O3 clang-x86-O2; do line $mode corpus/$c $extra; done
done
grep -v -x -F -f <(echo "$EARLY_ORACLE" | tr '|' '\n') "$ojobs" > "$ojobs.rest"
xargs -P $ORACLE_JOBS -L 1 "$BASH" -c 'oracle_one "$@"' _ < "$ojobs.rest"
wait "${early_oracle[@]}"
for mode in 0 1; do
  echo "PROGRAM-ORACLE FORWARD=$mode"
  extra=""; [ "$mode" = 1 ] && extra="--forward"
  for args in "v2-win-debug-full $extra" "v3-win-release-full $extra" "v3-win32-release-full $extra" "zlib $extra" \
      "ue-dll-debuggame $extra" "ue-dll-development $extra" "v2-win-debug-full --models $extra" \
      "v3-win-release-full --models $extra" "zlib --models $extra" "corpus/clang-x64-O0 $extra" \
      "corpus/clang-x64-O2 $extra" "corpus/gcc-x64-O3 $extra" "corpus/clang-x86-O2 $extra"; do
    tag=$(echo "$mode $args" | sed 's/ *$//' | tr ' /' '__')
    cat "$LOG/oracle.$tag.out" 2>/dev/null || echo "$mode $args NOT RUN"
    { [ -s "$LOG/oracle.$tag.out" ] && ! grep -q ' ERROR$' "$LOG/oracle.$tag.out"; } || fail "oracle $mode $args"
  done
done
stamp "TIMES (s, peak KB)"
for f in "$LOG"/*.time; do echo "$(basename $f .time) $(tail -1 $f)"; done | sort -k2 -n -r | head -12
stamp GATEDONE
finish
