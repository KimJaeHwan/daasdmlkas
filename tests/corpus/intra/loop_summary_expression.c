/* Header-tested loops for terminal-state summaries. Compile x64 Mach-O -O0.
 * The naked fixture deliberately keeps the ORIGINAL counter test at entry;
 * the engine receives only its extracted p-code, not this source signature.
 */
typedef unsigned long long word;
#define CASE __attribute__((noinline, visibility("default")))

__attribute__((naked, noinline, visibility("default")))
word case_summary_register(word initial, word step, word count) {
    __asm__ volatile(
        "movq %rdi, %rax\n"
        "1: cmpq $0, %rdx\n"
        "je 2f\n"
        "addq %rsi, %rax\n"
        "subq $1, %rdx\n"
        "jmp 1b\n"
        "2: retq\n");
}

CASE word case_summary_memory(word initial, word step, word count) {
    volatile word cell = initial;
    volatile word remaining = count;
    while (remaining != 0) {
        cell = cell + step;
        remaining -= 1;
    }
    return cell;
}

CASE word case_summary_narrow(word initial, word step, word count) {
    volatile unsigned char cell = (unsigned char)initial;
    volatile word remaining = count;
    while (remaining != 0) {
        cell = (unsigned char)(cell + (unsigned char)step);
        remaining -= 1;
    }
    return cell;
}
