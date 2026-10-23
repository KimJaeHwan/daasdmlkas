/* A real compiled indirect caller and an original two-RETURN callee.
 *
 * clang -target x86_64-apple-macos11 -O2 -mllvm -enable-tail-merge=false \
 *   -fno-stack-protector -fno-optimize-sibling-calls -nostdlib -dynamiclib \
 *   -lSystem -o <new-output>/multi_return_target.dylib multi_return_target.c
 *
 * The distinct harmless nop barriers keep the compiler from merging the two
 * exits. They do not supply a call result or modify the pointer/memory model.
 * Export _case_multi_return_target (the Mach-O symbol); its reference closure
 * includes both targets.
 * The regression must count the exported raw RETURNs, not the C return tokens.
 */

#define FIXTURE_FN __attribute__((noinline, visibility("default")))
typedef unsigned int value_t;
typedef value_t (*writer_t)(value_t *, value_t);

FIXTURE_FN value_t multi_return_a(value_t *p, value_t x) {
    if (x & 1u) {
        *p = x + 3u;
        __asm__ volatile("nop # odd" : "+a"(x));
        return x + 16u;
    }
    *p = x + 9u;
    __asm__ volatile("nop # even" : "+a"(x));
    return x + 32u;
}

FIXTURE_FN value_t multi_return_b(value_t *p, value_t x) {
    *p = x + 2u;
    return x + 32u;
}

FIXTURE_FN value_t case_multi_return_target(value_t selector, value_t x) {
    writer_t volatile table[2];
    table[0] = multi_return_a;
    table[1] = multi_return_b;
    value_t output = 0;
    value_t returned = table[selector & 1u](&output, x);
    return output + returned;
}
