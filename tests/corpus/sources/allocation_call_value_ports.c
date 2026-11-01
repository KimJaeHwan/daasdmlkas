/* Actual compiler fixture for a caller-owned allocation, not libc proof.
 * Empty register asm prevents LLVM's returned-argument substitution at the
 * call site; its real machine instructions still return the input bytes.
 * Volatile accesses keep the pointer spill and payload STORE/LOAD observable.
 */
#include <stdint.h>
#include <stdlib.h>

#define PUBLIC __attribute__((noinline, visibility("default")))
#define LEAF __attribute__((noinline))

static LEAF void *allocation_echo_register(void *pointer)
{
    __asm__ volatile("" : "+r"(pointer) :: "memory");
    return pointer;
}

static LEAF void *allocation_echo_offset(void *pointer)
{
    __asm__ volatile("" : "+r"(pointer) :: "memory");
    return (unsigned char *)pointer + 4;
}

static LEAF void *allocation_echo_memory(void *volatile *slot)
{
    return *slot;
}

PUBLIC uint32_t case_allocation_echo_register(uint32_t value)
{
    void *pointer = malloc(8);
    if (!pointer) return 0;
    volatile uint32_t *returned = allocation_echo_register(pointer);
    *returned = value;
    uint32_t result = *returned;
    free(pointer);
    return result;
}

PUBLIC uint32_t case_allocation_echo_offset(uint32_t value)
{
    void *pointer = malloc(8);
    if (!pointer) return 0;
    volatile uint32_t *returned = allocation_echo_offset(pointer);
    *returned = value;
    uint32_t result = *returned;
    free(pointer);
    return result;
}

PUBLIC uint32_t case_allocation_echo_memory(uint32_t value)
{
    void *pointer = malloc(8);
    if (!pointer) return 0;
    void *volatile saved = pointer;
    volatile uint32_t *returned = allocation_echo_memory(&saved);
    *returned = value;
    uint32_t result = *returned;
    free(pointer);
    return result;
}

extern void allocation_unknown_barrier(void);

PUBLIC uint32_t case_allocation_echo_barrier(uint32_t value)
{
    void *pointer = malloc(8);
    if (!pointer) return 0;
    volatile uint32_t *returned = allocation_echo_register(pointer);
    allocation_unknown_barrier();
    *returned = value;
    uint32_t result = *returned;
    free(pointer);
    return result;
}
