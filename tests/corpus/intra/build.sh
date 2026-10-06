#!/usr/bin/env bash
# Build the call-free verification corpus in several compiler/optimization/arch
# variants. Run from Git Bash on Windows (clang+lld, MinGW gcc).
# Output: tests/corpus/intra/build/<variant>/<file>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/intra_corpus.c"
OUT="$HERE/build"
mkdir -p "$OUT"
elf() {  # name target opt [extra...]
  local name=$1 target=$2 opt=$3; shift 3
  mkdir -p "$OUT/$name"
  clang --target="$target" "$opt" -g0 -fPIC -fno-stack-protector -nostdlib -shared \
        -fuse-ld=lld "$@" -o "$OUT/$name/libintra.so" "$SRC"
}
elf clang-x64-O0 x86_64-linux-gnu -O0
elf clang-x64-O2 x86_64-linux-gnu -O2
elf clang-x64-O3 x86_64-linux-gnu -O3 -mavx2
elf clang-x86-O0 i686-linux-gnu -O0
elf clang-x86-O2 i686-linux-gnu -O2
mkdir -p "$OUT/gcc-x64-O2-rep" "$OUT/gcc-x64-O3"
gcc -O2 -mstringop-strategy=rep_byte -shared -o "$OUT/gcc-x64-O2-rep/intra.dll" "$SRC"
gcc -O3 -march=x86-64-v2 -shared -o "$OUT/gcc-x64-O3/intra.dll" "$SRC"
ls -la "$OUT"/*/
