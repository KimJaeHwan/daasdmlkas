#!/usr/bin/env bash
# Mac Studio (Apple silicon) setup for the TBR G2b home work. Results must equal the office runs; only speed differs.
# Needs: Xcode command line tools (clang as gcc), git, Homebrew python@3.14, network (decoder sources, pip).
#
# usage:
#   bash setup_home_mac.sh <dir with the two zips>      (e.g. ~/Downloads)
# env (defaults in env.sh): REPO=~/work/daasdmlkas  DATA=~/tbr_data
set -euo pipefail
ZIPS=${1:?dir holding tbr_g2b_home_data_2026-11-27.zip and tbr_g2b_home_results_2026-11-27.zip}
HERE=$(cd "$(dirname "$0")" && pwd)
export REPO=${REPO:-$HOME/work/daasdmlkas} DATA=${DATA:-$HOME/tbr_data}

echo "== 1. git: repo + worktrees at the office relative paths"
[ -d "$REPO/.git" ] || git clone https://github.com/KimJaeHwan/daasdmlkas "$REPO"
cd "$REPO"
git fetch origin home/tbr-g2b-2026-11-27 feat/g1-decode-check docs/ghidra-independence
mkdir -p .census6
[ -d .census6/wt_lint ] || git worktree add .census6/wt_lint -b home/tbr-g2b-2026-11-27 origin/home/tbr-g2b-2026-11-27
[ -d .census6/wt_g2b_base ] || git worktree add --detach .census6/wt_g2b_base c15a29a
[ -d .census6/wt_docs ] || git worktree add .census6/wt_docs -b docs/ghidra-independence origin/docs/ghidra-independence

echo "== 2. data: verify and unzip into \$DATA (the office /root layout)"
mkdir -p "$DATA"
cd "$ZIPS"
shasum -a 256 -c tbr_g2b_home_data_2026-11-27.zip.sha256
shasum -a 256 -c tbr_g2b_home_results_2026-11-27.zip.sha256
python3 - "$ZIPS" "$DATA" <<'PY'
import sys, zipfile
for name in ("tbr_g2b_home_data_2026-11-27.zip", "tbr_g2b_home_results_2026-11-27.zip"):
    with zipfile.ZipFile(f"{sys.argv[1]}/{name}") as z:
        z.extractall(sys.argv[2])
        print(name, len(z.namelist()), "files")
PY

echo "== 3. venv (Python 3.14) with the office package versions"
PY314=${PY314:-$(command -v python3.14)}
[ -x "$REPO/.venv-tdo/bin/python" ] || "$PY314" -m venv "$REPO/.venv-tdo"
grep -v '^-e ' "$REPO/.census6/wt_lint/docs/handoff_tbr/requirements_wsl_tdo.txt" > /tmp/req_tdo.txt
"$REPO/.venv-tdo/bin/pip" install -q -r /tmp/req_tdo.txt
"$REPO/.venv-tdo/bin/pip" install -q -e "$REPO/.census6/wt_lint"

echo "== 4. decoders: rebuild for this machine (pinned iced 1.22.0 / Zydis v4.1.1 / XED v2026.08.23)"
source "$HERE/env.sh"
cd "$C/wt_lint"
DEST="$G1_DECODERS" PY="$PY" bash tools/decode_check/build_decoders.sh
PYTHONPATH=src:tools/decode_check "$PY" - <<'PY'
import decoders
for hexs, flow in (("e800000000", "call_near"), ("0f34", "sysenter"), ("ff25aaaaaaaa", "jmp_near")):
    b = decoders.ballot(bytes.fromhex(hexs) + b"\x90" * 10, 0x140001000)
    assert all(d.status == "ok" and d.flow == flow for ds in b.values() for d in ds), (hexs, b)
print("decoders ok")
PY

echo "== 5. tests (both seeds; 0 skipped expected)"
for s in 0 1; do
  PYTHONHASHSEED=$s PYTHONPATH=src "$PY" -m pytest -q tests/intra/test_decode_check.py -rs | tail -3
done

echo "== 6. platform parity: the same code (7a3cefe) on this machine vs the office outputs"
bash "$HERE/parity_mac.sh"
