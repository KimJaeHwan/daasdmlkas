# Source this in every mac shell:  source <repo>/.census6/wt_lint/docs/handoff_tbr/mac/env.sh
# Paths mirror the office layout with two roots: REPO (git) and DATA (the unzipped /root data).
export REPO=${REPO:-$HOME/work/daasdmlkas}
export DATA=${DATA:-$HOME/tbr_data}
export PY=${PY:-$REPO/.venv-tdo/bin/python}
export G1_DECODERS=${G1_DECODERS:-$DATA/g1_decoders}     # decoders.py reads this (default /root/g1_decoders)
export PYTHONHASHSEED=${PYTHONHASHSEED:-0}
export C=$REPO/.census6
gen() { ls -d "$DATA/$1"/*/ 2>/dev/null | grep -v '\.logs' | head -1 | sed 's#/$##'; }
export ZL=$(gen tdo_bundles3/zlib) V3=$(gen tdo_bundles3/v3-win-release-full) NT=$(gen tdo_g2/ntdll) \
       UE=$(gen tdo_bundles3/ue-core-probe) CL=$(gen tdo_bundles4/corpus/clang-x64-O0)
export CLANG_SRC=$DATA/g1_runs/main_src_1828683/src     # clang Bundle admission needs main 1828683's engine
