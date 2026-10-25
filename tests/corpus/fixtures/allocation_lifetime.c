/* Small original-binary allocation/lifetime corpus.
 *
 * Compile callers at -O1; the helper deliberately keeps its two physical
 * pointer inputs at -O0. Volatile accesses retain distinct raw STORE/LOADs,
 * and unroll(disable) retains the two-iteration CFG backedges. Neither is an
 * allocation extent, success, callback, or lifetime assumption for analysis.
 *
 * The released branch never reads an old pointer. Address reuse in the
 * existing p-code allocator oracle is a finite execution observation, not
 * a claim about a native allocator or all executions of this binary.
 */
#include <stdint.h>
#include <stdlib.h>

#define EXPORTED __attribute__((noinline, visibility("default")))

static __attribute__((noinline, optnone)) int
allocation_alias_helper(volatile uint64_t *first, volatile uint64_t *second,
                        unsigned release)
{
    if (release & 1u) {
        free((void *)second);
        return 1;
    }
    *first = *second ^ UINT64_C(0x5a5a);
    return 0;
}

EXPORTED uint64_t case_alias(uint64_t value, unsigned release)
{
    volatile uint64_t *p = malloc(8);
    if (!p)
        return 0;
    volatile uint64_t *q = p;
    *p = value;
    if (allocation_alias_helper(p, q, release))
        return 0;
    uint64_t result = *q;
    free((void *)p);
    return result;
}

EXPORTED uint64_t case_loop(uint64_t seed)
{
    uint64_t result = 0;
#pragma clang loop unroll(disable)
    for (unsigned i = 0; i < 2; ++i) {
        volatile uint64_t *p = malloc(8);
        if (!p)
            return result;
        *p = seed + i;
        result ^= *p;
        free((void *)p);
    }
    return result;
}

EXPORTED uint64_t case_outer_loop(uint64_t seed)
{
    volatile uint64_t *p = malloc(8);
    if (!p)
        return 0;
    uint64_t result = 0;
#pragma clang loop unroll(disable)
    for (unsigned i = 0; i < 2; ++i) {
        *p = seed + i;
        result ^= *p;
    }
    free((void *)p);
    return result;
}

/* Only a positive-size failure path may reuse the old allocation. The
 * successful path never reads the old alias and frees only the new result.
 */
EXPORTED uint64_t case_resize_failure(uint64_t seed)
{
    volatile uint64_t *p = malloc(8);
    if (!p)
        return 0;
    void *next = realloc((void *)p, 16);
    if (!next) {
        *p = seed;
        uint64_t result = *p;
        free((void *)p);
        return result;
    }
    free(next);
    return 0;
}

/* A zero-size NULL result does not license an old-pointer access. Its
 * implementation-dependent lifecycle remains a separate negative query.
 */
EXPORTED uint64_t case_resize_zero(uint64_t seed)
{
    volatile uint64_t *p = malloc(8);
    if (!p)
        return 0;
    *p = seed;
    void *next = realloc((void *)p, 0);
    if (next)
        free(next);
    return 0;
}

/* A known release(NULL) is intentionally still a real call: its lifecycle
 * transition does not end the object passed through these two full ports.
 */
static __attribute__((noinline, optnone)) void
allocation_keep_helper(volatile uint64_t *first, volatile uint64_t *second)
{
    *first = *second ^ UINT64_C(0x5a5a);
    free(NULL);
}

EXPORTED uint64_t case_alias_keep(uint64_t value)
{
    volatile uint64_t *p = malloc(8);
    if (!p)
        return 0;
    volatile uint64_t *q = p;
    *p = value;
    allocation_keep_helper(p, q);
    uint64_t result = *q;
    free((void *)p);
    return result;
}
