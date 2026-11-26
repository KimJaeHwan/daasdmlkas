#!/usr/bin/env bash
# G1 decode_check: fetch and build the three pinned decoders into $DEST (default /root/g1_decoders).
# Diagnostic-tool dependencies only (never engine run dependencies). Owner OK to download: 2026-11-24.
#   iced-x86 1.22.0 (PyPI)          -> $DEST/py (pip --target; the engine venv is not touched)
#   Zydis v4.1.1 amalgamated        -> $DEST/lib/libdc_zydis.so  (+ zydis_shim.c)
#   XED v2026.08.23 + mbuild        -> $DEST/lib/libdc_xed.so    (+ xed_shim.c)
# Writes $DEST/manifest.json with versions, commits and sha256 of every artifact.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="${DEST:-/root/g1_decoders}"
PY="${PY:-/root/venvs/tdo/bin/python}"
ICED_VERSION="1.22.0"
ZYDIS_TAG="v4.1.1"
ZYDIS_COMMIT="a2278f1d254e492f6a6b39f6cb5d1f5d515659dc"
XED_TAG="v2026.08.23"
XED_COMMIT="0bcb6237345c5066726dcc08b3d87928df3b5b26"   # (the annotated tag object is c6424829)
MBUILD_TAG="v2026.08.23"
MBUILD_COMMIT="1b437e409221a2b5703b4d8896baa20d43e4ba1a"

mkdir -p "$DEST/src" "$DEST/lib" "$DEST/py"

# -- iced-x86
"$PY" -m pip install --quiet --no-deps --target "$DEST/py" "iced-x86==${ICED_VERSION}"

# -- Zydis: pinned tag (commit verified) + zycore submodule, amalgamated by the repo's own script,
#    compiled with our shim (v4.1.1 publishes no release assets)
cd "$DEST/src"
if [ ! -d zydis ]; then
    git clone --quiet --depth 1 --branch "$ZYDIS_TAG" --recurse-submodules --shallow-submodules         https://github.com/zyantific/zydis.git zydis
fi
actual="$(git -C zydis rev-parse HEAD)"
if [ "$actual" != "$ZYDIS_COMMIT" ]; then
    echo "commit mismatch for zydis: $actual != $ZYDIS_COMMIT" >&2
    exit 1
fi
if [ ! -f zydis/amalgamated-dist/Zydis.c ]; then
    (cd zydis && python3 assets/amalgamate.py >/dev/null)
fi
ZYDIS_DIR="$DEST/src/zydis/amalgamated-dist"
gcc -O2 -fPIC -shared -DZYDIS_STATIC_BUILD -DZYCORE_STATIC_BUILD -I"$ZYDIS_DIR" -I"$HERE/decoders"     "$ZYDIS_DIR/Zydis.c" "$HERE/decoders/zydis_shim.c" -o "$DEST/lib/libdc_zydis.so"

# -- XED: pinned tags, commits verified, static build, linked into our shim
cd "$DEST/src"
for repo in xed:$XED_TAG:$XED_COMMIT mbuild:$MBUILD_TAG:$MBUILD_COMMIT; do
    name="${repo%%:*}"; rest="${repo#*:}"; tag="${rest%%:*}"; commit="${rest#*:}"
    if [ ! -d "$name" ]; then
        git clone --quiet --depth 1 --branch "$tag" "https://github.com/intelxed/${name}.git" "$name"
    fi
    actual="$(git -C "$name" rev-parse HEAD)"
    if [ "$actual" != "$commit" ]; then
        echo "commit mismatch for $name: $actual != $commit" >&2
        exit 1
    fi
done
cd "$DEST/src/xed"
if [ ! -f obj/wkit/lib/libxed.a ]; then
    "$PY" mfile.py --static >/dev/null   # (the working kit obj/wkit holds include/ and lib/libxed.a)
fi
gcc -O2 -fPIC -shared -pthread -I"$DEST/src/xed/obj/wkit/include" -I"$HERE/decoders" \
    "$HERE/decoders/xed_shim.c" "$DEST/src/xed/obj/wkit/lib/libxed.a" -o "$DEST/lib/libdc_xed.so"
# the XED instruction-table dump for the ordinary-form generator (isa_ordinary_gen.py) and its tests
gcc -O1 -I"$DEST/src/xed/obj/wkit/include" "$HERE/decoders/xed_catalogue.c" \
    "$DEST/src/xed/obj/wkit/lib/libxed.a" -o "$DEST/xed_catalogue"
"$DEST/xed_catalogue" > "$DEST/xed_catalogue.tsv"

# -- manifest
"$PY" - "$DEST" <<'PYEOF'
import hashlib, json, sys
from pathlib import Path
dest = Path(sys.argv[1])
def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
wheel = sorted((dest / "py").glob("iced_x86*/RECORD"))
manifest = {
    "iced-x86": {"version": "1.22.0", "record_sha256": digest(wheel[0]) if wheel else None},
    "zydis": {"tag": "v4.1.1", "commit": "a2278f1d254e492f6a6b39f6cb5d1f5d515659dc",
              "zycore_commit": "0b2432ced0884fd152b471d97ecf0258ff4d859f",
              "amalgamated_sha256": digest(dest / "src" / "zydis" / "amalgamated-dist" / "Zydis.c"),
              "library_sha256": digest(dest / "lib" / "libdc_zydis.so")},
    "xed": {"tag": "v2026.08.23", "commit": "0bcb6237345c5066726dcc08b3d87928df3b5b26",
            "mbuild_commit": "1b437e409221a2b5703b4d8896baa20d43e4ba1a",
            "libxed_sha256": digest(dest / "src" / "xed" / "obj" / "wkit" / "lib" / "libxed.a"),
            "library_sha256": digest(dest / "lib" / "libdc_xed.so")},
}
(dest / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
print(json.dumps(manifest, indent=1, sort_keys=True))
PYEOF
