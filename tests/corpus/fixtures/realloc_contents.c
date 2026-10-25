/* Original-binary content-copy cases, not native allocator certification.
 * The NULL branch retains and frees only the original allocation. Success
 * reads only the new pointer, within min(old size, new size). No old alias
 * is dereferenced after success and no uninitialized grown tail is read.
 */
#include <stdint.h>
#include <stdlib.h>

#define EXPORTED __attribute__((noinline, visibility("default")))
struct payload {
    volatile uint32_t low, high, spare, tail;
};

/* Volatile field writes keep three original STORE4 operations. memcpy
 * observes their object representation without incompatible typed access.
 */
#define INITIALIZE(p, seed) do { \
    (p)->low = (uint32_t)(seed); \
    (p)->high = (uint32_t)((seed) >> 32); \
    (p)->tail = UINT32_C(0x76543210); \
} while (0)
#define RESIZE_OR_RETURN(p, next, size) do { \
    (next) = realloc((p), (size)); \
    if (!(next)) { free(p); return 0; } \
} while (0)
#define OBSERVE(next, result) do { \
    __asm__ volatile("" ::: "memory"); \
    __builtin_memcpy(&(result), (next), sizeof(result)); \
} while (0)

EXPORTED uint64_t case_realloc_grow(uint64_t seed)
{
    struct payload *p = malloc(16);
    if (!p) return 0;
    INITIALIZE(p, seed);
    void *next;
    RESIZE_OR_RETURN(p, next, 32);
    uint64_t result;
    OBSERVE(next, result);
    free(next);
    return result;
}

EXPORTED uint64_t case_realloc_shrink(uint64_t seed)
{
    struct payload *p = malloc(16);
    if (!p) return 0;
    INITIALIZE(p, seed);
    void *next;
    RESIZE_OR_RETURN(p, next, 8);
    uint64_t result;
    OBSERVE(next, result);
    free(next);
    return result;
}

EXPORTED uint64_t case_realloc_partial(uint64_t seed)
{
    struct payload *p = malloc(16);
    if (!p) return 0;
    INITIALIZE(p, seed);
    void *next;
    RESIZE_OR_RETURN(p, next, 32);
    const uint16_t patch = UINT16_C(0xbeef);
    __builtin_memcpy((unsigned char *)next + 2, &patch, sizeof(patch));
    uint64_t result;
    OBSERVE(next, result);
    free(next);
    return result;
}

/* Its implementation is deliberately absent: the static CALL must remain
 * a barrier. A test-only external oracle may choose a concrete mutation.
 */
extern void realloc_opaque_mutate(void *pointer);

EXPORTED uint64_t case_realloc_opaque(uint64_t seed)
{
    struct payload *p = malloc(16);
    if (!p) return 0;
    INITIALIZE(p, seed);
    void *next;
    RESIZE_OR_RETURN(p, next, 32);
    realloc_opaque_mutate(next);
    uint64_t result;
    OBSERVE(next, result);
    free(next);
    return result;
}
