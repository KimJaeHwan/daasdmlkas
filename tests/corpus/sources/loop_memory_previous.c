/* Real compiled testbed, not an external-library coverage claim.
 * Volatile preserves the original LOAD/STORE and their source order.
 * p starts one word into an allocated array, so p[-1] is valid at entry.
 */
typedef __UINT64_TYPE__ word;
typedef unsigned char byte;
_Static_assert(sizeof(word) == 8, "previous-visit fixtures require 8-byte words");

#define CASE __attribute__((noinline, used, visibility("default")))

CASE word previous_slot(volatile word *p, word count, word value)
{
    word result = 0;
    while (count != 0) {
        result ^= p[-1];
        *p = value + count;
        ++p;
        --count;
    }
    return result;
}

CASE word previous_partial(volatile word *p, word count, word value, byte patch)
{
    word result = 0;
    while (count != 0) {
        ((volatile byte *)(p - 1))[3] = patch;
        result ^= p[-1];
        *p = value + count;
        ++p;
        --count;
    }
    return result;
}

CASE word previous_bypass(volatile word *p, word count, word value)
{
    word result = 0;
    while (count != 0) {
        result ^= p[-1];
        if ((count & 1) != 0)
            *p = value + count;
        ++p;
        --count;
    }
    return result;
}
