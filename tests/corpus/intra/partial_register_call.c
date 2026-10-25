/* Compile for x86_64. Inline assembly keeps the actual narrow register writes
 * observable in the binary; it supplies no analyzer summary or call result.
 * The callee's generic pointer aliases are resolved only in the caller.
 */
typedef unsigned long long word;

__attribute__((noinline, visibility("default")))
word partial_register_source(volatile word *p, volatile word *q, word value) {
    *q = value;
    return *p + 1;
}

#define CASE(name, instruction) \
    __attribute__((noinline, visibility("default"))) \
    word name(word seed) { \
        volatile word cell = 0; \
        word value = partial_register_source(&cell, &cell, seed); \
        __asm__ volatile(instruction : "+a"(value)); \
        return value + 5; \
    }

CASE(case_partial_al, "movb $0xaa, %b0")
CASE(case_partial_ah, "movb $0xbb, %h0")
CASE(case_partial_ax, "movw $0xccdd, %w0")
CASE(case_partial_eax, "movl $0xabcdef01, %k0")
