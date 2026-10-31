/* Native-binary fixtures for occurrence-qualified loop memory edges.
 * Volatile accesses are deliberate: the compiler must emit each original
 * STORE/LOAD, rather than forward the stored value in a register.
 * These are testbed functions, not external-library evidence.
 */
/* Keep the logical value width identical on LP64 macOS and LLP64 Windows;
 * a 32-bit target may legitimately lower one access to two DWORD accesses.
 */
typedef __UINT64_TYPE__ word;
_Static_assert(sizeof(word) == 8, "loop read-from fixtures require 8-byte words");
typedef unsigned char byte;

#define CASE __attribute__((noinline, used, visibility("default")))

CASE word loop_rf_write_read(volatile word *p, word count, word value)
{
    word result = 0;
    while (count != 0) {
        *p = value + count;
        result ^= *p;
        ++p;
        --count;
    }
    return result;
}

CASE word loop_rf_partial(volatile word *p, word count, word value, byte patch)
{
    word result = 0;
    while (count != 0) {
        *p = value;
        ((volatile byte *)p)[3] = patch;
        result ^= *p;
        ++p;
        --count;
    }
    return result;
}

CASE word loop_rf_conditional(volatile word *p, word count, word value)
{
    word result = 0;
    while (count != 0) {
        if ((count & 1) != 0)
            *p = value;
        result ^= *p;
        ++p;
        --count;
    }
    return result;
}

CASE word loop_rf_read_first(volatile word *p, word count, word value)
{
    word result = 0;
    while (count != 0) {
        result ^= *p;
        *p = value + count;
        ++p;
        --count;
    }
    return result;
}
