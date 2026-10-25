/* Actual x64 conditional narrow writes; reuses the v9 aliasing call body. */
#include "partial_register_call.c"

#define CONDITIONAL_CASE(name, instruction) \
    __attribute__((noinline, visibility("default"))) \
    word name(word seed, word flag) { \
        volatile word cell = 0; \
        word value = partial_register_source(&cell, &cell, seed); \
        if (flag & 1) { __asm__ volatile(instruction : "+a"(value)); } \
        return value + 5; \
    }

CONDITIONAL_CASE(case_conditional_al, "movb $0xaa, %b0")
CONDITIONAL_CASE(case_conditional_ah, "movb $0xbb, %h0")
CONDITIONAL_CASE(case_conditional_ax, "movw $0xccdd, %w0")

__attribute__((noinline, visibility("default")))
word case_conditional_from_call(word seed) {
    volatile word cell = 0;
    word value = partial_register_source(&cell, &cell, seed);
    if (value & 1) { __asm__ volatile("movb $0xbb, %h0" : "+a"(value)); }
    return value + 5;
}
