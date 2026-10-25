/* The empty volatile asm keeps register recurrences from algebraic folding.
 * All actual value operations still come from the original binary p-code.
 */
typedef unsigned long long word;

__attribute__((noinline, visibility("default")))
word case_register_recurrence(word value, word step, word count) {
    while (count != 0) {
        __asm__ volatile("" : "+r"(value));
        value += step;
        count -= 1;
    }
    return value;
}

__attribute__((noinline, visibility("default")))
word case_memory_recurrence(word initial, word step, word count) {
    volatile word cell = initial;
    while (count != 0) {
        cell = cell + step;
        count -= 1;
    }
    return cell;
}
