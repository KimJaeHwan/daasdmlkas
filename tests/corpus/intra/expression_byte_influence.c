/* Real instruction fixtures for byte influence. No engine result injection. */
typedef unsigned long long word;

__attribute__((noinline)) word case_influence_add(word x, word y) {
    return x + y;
}

__attribute__((noinline)) word case_influence_cancel(word x, word y) {
    word mixed = (x ^ y) + ((x & y) << 1);
    /* Preserve the MBA instructions across compiler algebraic folding.
       Empty asm emits no instruction or hidden memory/register mutation. */
    __asm__ volatile ("" : "+r" (mixed));
    return mixed - y;
}
