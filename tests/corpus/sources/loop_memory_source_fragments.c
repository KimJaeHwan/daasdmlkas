/* Real instruction fixtures, not evidence of external-library coverage.
 * ARM64 inserts one byte into D0; its upper seven bytes retain the seed.
 * The x64 path changes AL, but Ghidra may copy RAX before the STOSQ STORE;
 * that path is a re-packaging control, not a fragmented-STORE positive.
 * Its RDI post-update is discarded: the C loop independently advances p.
 * Thus both DF inputs are meaningful without assuming DF == 0.
 */
typedef __UINT64_TYPE__ word;
typedef unsigned char byte;
_Static_assert(sizeof(word) == 8, "source-fragment fixtures require 8-byte words");

#define CASE __attribute__((noinline, used, visibility("default")))

#if defined(__aarch64__)
#define WRITE_VALUE(p, seed, patch) \
    __asm__ volatile ("fmov d0, %x1\n\tins v0.b[0], %w2\n\tstr d0, [%x0]" \
                      : : "r" (p), "r" (seed), "r" ((unsigned int)(patch)) \
                      : "v0", "memory")
#elif defined(__x86_64__)
#define WRITE_VALUE(p, seed, patch) do { \
    word value = (seed); \
    volatile word *cursor = (p); \
    __asm__ volatile ("movb %b2, %b0\n\tstosq" \
                      : "+a" (value), "+D" (cursor) \
                      : "q" (patch) : "memory", "cc"); \
} while (0)
#else
#error "source-fragment fixtures require ARM64 or x64"
#endif

CASE word loop_source_fragments(volatile word *p, word count, word seed, byte patch)
{
    word result = 0;
    while (count != 0) {
        WRITE_VALUE(p, seed, patch);
        result ^= *p;
        ++p;
        --count;
    }
    return result;
}

CASE word loop_source_fragments_partial(volatile word *p, word count, word seed, byte patch)
{
    word result = 0;
    while (count != 0) {
        WRITE_VALUE(p, seed, patch);
        ((volatile byte *)p)[3] = (byte)(patch ^ 0x5a);
        result ^= *p;
        ++p;
        --count;
    }
    return result;
}
