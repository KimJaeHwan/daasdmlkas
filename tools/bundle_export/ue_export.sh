#!/usr/bin/env bash
# Export the 10_tdo_UE_testbed binaries to v2 Bundles (WSL):
#   cpp_like libtv2_cpp_like.so  P0/P1 x x64/x86   -> /root/tdo_bundles/ue-cpp-<P>-<arch>
#   UE module DLL (Development, DebugGame)          -> /root/tdo_bundles/ue-dll-<config>
# Case function names come from each tier's manifest. Names Ghidra cannot find
# (inlined / folded) are dropped one by one until the export succeeds.
# usage: ue_export.sh [only-tag]
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
TB=/mnt/d/01_gitproject/10_tdo_UE_testbed
names() {  # manifest -> --function-name args
  python3 - "$1" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
cases = m.get("cases", m) if isinstance(m, dict) else m
print(" ".join(f"--function-name {n}" for n in sorted({c["function"] for c in cases})))
PY
}
CPP_NAMES=$(names "$TB/cpp_like/manifests/"*.json)
UE_NAMES=$(names "$TB/unreal_playground/manifests/cases_v2_manifest.json")
TARGETS=(
  "ue-cpp-P0-x64|$TB/cpp_like/build/P0/x64/libtv2_cpp_like.so|$CPP_NAMES"
  "ue-cpp-P1-x64|$TB/cpp_like/build/P1/x64/libtv2_cpp_like.so|$CPP_NAMES"
  "ue-cpp-P0-x86|$TB/cpp_like/build/P0/x86/libtv2_cpp_like.so|$CPP_NAMES"
  "ue-cpp-P1-x86|$TB/cpp_like/build/P1/x86/libtv2_cpp_like.so|$CPP_NAMES"
  "ue-dll-development|$TB/unreal_playground/TraceUnrealPlayground/Binaries/Win64/UnrealEditor-TraceUnrealPlayground.dll|$UE_NAMES"
  "ue-dll-debuggame|$TB/unreal_playground/TraceUnrealPlayground/Binaries/Win64/UnrealEditor-TraceUnrealPlayground-Win64-DebugGame.dll|$UE_NAMES"
)
for item in "${TARGETS[@]}"; do
  IFS='|' read -r tag binary args <<< "$item"
  [ -n "${1:-}" ] && [ "$1" != "$tag" ] && continue
  out=/root/tdo_bundles/$tag
  rm -rf "$out" "$out.logs"
  exclude=()
  for attempt in $(seq 1 30); do
    log=$(timeout 7200 python3 "$REPO/tools/bundle_export/export_bundle.py" "$binary" $args \
          --output-root "$out" 2>&1)
    if echo "$log" | grep -q '^\[export\] published'; then
      echo "$tag: $(echo "$log" | grep '^\[export\] published' | sed 's/.*(/(/') excluded=${#exclude[@]} ${exclude[*]}"
      break
    fi
    script_log=$(echo "$log" | grep -o '/root[^ ]*script.log' | tail -1)
    missing=$(grep -o 'missing or ambiguous: [A-Za-z0-9_]*' "${script_log%script.log}ghidra.log" 2>/dev/null \
              | tail -1 | awk '{print $NF}')
    if [ -z "$missing" ]; then echo "$tag: EXPORT FAILED"; echo "$log" | tail -5; break; fi
    args=$(echo "$args" | sed "s/--function-name $missing\b//")
    exclude+=("$missing")
  done
done
