/* Actual-byte fixture: local simplification, shared choices and RAM effects.
 * No source/sink annotations or hand-rewritten p-code are used by the test.
 */
typedef unsigned long long word;

__attribute__((noinline)) word case_view_mba(word x, word y) {
    return (x ^ y) + ((x & y) << 1);
}

__attribute__((noinline, optnone)) word case_view_shared(word x, word y, word count, word selector) {
    volatile word left = x, right = x + 3;
    while (count) {
        if (selector) {
            left = (left ^ y) + ((left & y) << 1);
            right = right + y;
        } else {
            left = left + (y ^ 0x55);
            right = (right ^ (y ^ 0x55)) + ((right & (y ^ 0x55)) << 1);
        }
        --count;
    }
    return left ^ right;
}
