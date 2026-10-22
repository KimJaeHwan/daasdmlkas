/* Actual indirect-call fixture, without calls to runtime or library functions.
 *
 * Example x64 build on macOS (output must be a new temporary directory):
 *   clang -target x86_64-apple-macos11 -O1 -g0 -fno-stack-protector \
 *     -fno-optimize-sibling-calls -nostdlib -dynamiclib -lSystem \
 *     -o /private/tmp/NEW_DIRECTORY/multi_target_memory.dylib \
 *     tests/corpus/intra/multi_target_memory.c
 *
 * Export _case_multi_target_memory, _multi_memory_a and _multi_memory_b
 * (Mach-O's leading underscores) with tools/bundle_export/export_bundle.py. The
 * volatile local function table stays on the caller's stack, and its index
 * is a caller input. Both callees are noinline. Unsigned arithmetic makes the
 * expected wraparound independent of the host C implementation.
 */

#define FIXTURE_FN __attribute__((noinline, visibility("default")))

typedef unsigned int value_t;
typedef value_t (*writer_t)(value_t *, value_t);

FIXTURE_FN value_t multi_memory_a(value_t *p, value_t x) {
    *p = x + 1u;
    return x + 16u;
}

FIXTURE_FN value_t multi_memory_b(value_t *p, value_t x) {
    *p = x + 2u;
    return x + 32u;
}

FIXTURE_FN value_t case_multi_target_memory(value_t selector, value_t x) {
    writer_t volatile table[2];
    table[0] = multi_memory_a;
    table[1] = multi_memory_b;
    value_t output = 0;
    value_t returned = table[selector & 1u](&output, x);
    return output + returned;
}
