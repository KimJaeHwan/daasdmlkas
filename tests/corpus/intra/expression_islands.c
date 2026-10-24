/* Whole original binaries for conditional pure regions. No oracle injection.
 * The source function is deliberately withheld from engine analysis in the
 * opaque test but its REAL extracted body executes in the raw-pcode oracle.
 */
typedef unsigned long long word;

__attribute__((noinline)) word island_unavailable_source(word x) {
    return (x ^ 0x8e71b3d49526a0cfull) + 17;
}

static __attribute__((always_inline)) inline word region(word x, word y) {
    word a, b;
    /* Explicit, real register COPY producers are the two region boundaries. */
    __asm__ volatile ("movq %2, %0\n\tmovq %3, %1" : "=&r" (a), "=&r" (b) : "r" (x), "r" (y));
    word mixed = (a ^ b) + ((a & b) << 1);
    __asm__ volatile ("" : "+r" (mixed)); /* Preserve the actual MBA instructions. */
    return mixed ^ 0x91;
}

__attribute__((noinline)) word case_island_pure(word x, word y) {
    return region(x, y);
}

__attribute__((noinline)) word case_island_opaque(word x, word y) {
    word value = island_unavailable_source(x);
    return region(value, y);
}

__attribute__((noinline)) word case_island_shared(word x, word y, word selector) {
    word a, b;
    /* Keep a real diamond and TWO correlated SSA joins, not free choices. */
    __asm__ volatile (
        "movq %2, %0\n\tmovq %3, %1\n\ttestq %4, %4\n\tjz 1f\n\t"
        "addq $7, %0\n\taddq $7, %1\n\tjmp 2f\n"
        "1:\n\taddq $9, %0\n\taddq $9, %1\n2:"
        : "=&r" (a), "=&r" (b) : "r" (x), "r" (y), "r" (selector) : "cc");
    return a - b;
}
