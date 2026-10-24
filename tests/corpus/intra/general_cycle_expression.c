/* General cyclic expression fixtures, without calls to runtime/library functions.
 *
 * Compile as x64 at -O0 (no LTO), then export these six functions with the
 * existing Ghidra 12.0.4 bundle exporter. Volatile cells preserve original
 * RAM operations. Empty asm is a compiler barrier, not a supplied value.
 * CFG structure must still be checked in the resulting original p-code:
 * source labels alone are not evidence of an irreducible/multi-latch loop.
 *
 * Every input is unsigned. Counters are bounded and decremented on every
 * cyclic visit, so count=0/1/3/5 and selector=0/1/2 are terminating inputs.
 * Execution checks use extracted p-code, not a claim of native execution.
 */

typedef unsigned long long word;
#define CASE __attribute__((noinline, visibility("default")))
#define BARRIER() __asm__ volatile("" : : : "memory")

CASE word case_cycle_nested(word seed, word step, word count, word selector) {
    volatile word value = seed;
    word outer = count & 7u;
    while (outer != 0) {
        word inner = (selector & 3u) + 1u;
        while (inner != 0) {
            value = value + step;
            inner -= 1u;
        }
        value = value ^ outer;
        outer -= 1u;
    }
    return value;
}

CASE word case_cycle_multi_update(word seed, word step, word count, word selector) {
    volatile word value = seed;
    word remaining = count & 7u;
    while (remaining != 0) {
        if (((selector ^ remaining) & 1u) != 0)
            value = value + step;
        else
            value = value ^ (step + remaining);
        value = value + remaining;
        remaining -= 1u;
    }
    return value;
}

CASE word case_cycle_multi_backedge(word seed, word step, word count, word selector) {
    volatile word value = seed;
    word remaining = count & 7u;
again:
    if (remaining == 0)
        return value;
    if (((selector ^ remaining) & 1u) != 0) {
        value = value + step;
        remaining -= 1u;
        BARRIER();
        goto again;
    }
    value = value ^ step;
    remaining -= 1u;
    BARRIER();
    goto again;
}

CASE word case_cycle_irreducible(word seed, word step, word count, word selector) {
    volatile word value = seed;
    word remaining = count & 7u;
    if ((selector & 1u) != 0)
        goto right;
left:
    if (remaining == 0)
        goto done;
    value = value + step;
    remaining -= 1u;
    BARRIER();
    if ((remaining & 1u) != 0)
        goto right;
    goto left;
right:
    if (remaining == 0)
        goto done;
    value = value ^ step;
    remaining -= 1u;
    BARRIER();
    if ((remaining & 1u) != 0)
        goto left;
    goto right;
done:
    return value;
}

CASE word case_cycle_sequential(word seed, word step, word count, word selector) {
    volatile word value = seed;
    word remaining = count & 7u;
    while (remaining != 0) {
        value = value + step;
        remaining -= 1u;
    }
    remaining = selector & 7u;
    while (remaining != 0) {
        value = value ^ (step + remaining);
        remaining -= 1u;
    }
    return value;
}

CASE word case_cycle_memory(word seed, word step, word count, word selector) {
    volatile word cell = seed;
    volatile word shadow = seed + 1u;
    word remaining = count & 7u;
    while (remaining != 0) {
        cell = cell + step;
        if (((selector ^ remaining) & 1u) != 0)
            shadow = cell ^ shadow;
        else
            cell = shadow + step;
        remaining -= 1u;
    }
    return cell ^ shadow;
}
