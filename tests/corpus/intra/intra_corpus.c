/*
 * Call-free verification corpus for the graph-fidelity oracle.
 *
 * Every function is call-free C (no library calls) so the interpreter oracle
 * can execute it in isolation; optimizers turn these patterns into the
 * machine-code shapes the graph must represent: jump tables, cmov, rep
 * movs/stos, SIMD, unrolled and nested loops, multiple exits.
 * No expected answers are needed: the oracle compares executions with the graph.
 */
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define EXPORT __declspec(dllexport) __attribute__((noinline))
#else
#define EXPORT __attribute__((visibility("default"), noinline))
#endif

typedef struct Big { int a[24]; long long tag; char name[16]; } Big;
typedef struct Node { struct Node *next; int value; } Node;
typedef struct Flags { unsigned mode : 3; unsigned on : 1; unsigned level : 4; unsigned rest : 24; } Flags;

EXPORT int sw_dense(int x) {
    switch (x) {
    case 0: return 11; case 1: return 23; case 2: return x * 7; case 3: return 5;
    case 4: return x + 100; case 5: return -9; case 6: return x << 3; case 7: return 77;
    default: return -1;
    }
}

EXPORT int sw_sparse(int x, int y) {
    switch (x) {
    case 1: return y + 1; case 10: return y * 2; case 100: return y ^ 0x55;
    case 1000: return y - 3; case 4096: return ~y; default: return 0;
    }
}

EXPORT int clamp_int(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

EXPORT int min_max_sum(const int *p, int n) {
    int lo = p[0], hi = p[0];
    for (int i = 1; i < n; i++) { if (p[i] < lo) lo = p[i]; if (p[i] > hi) hi = p[i]; }
    return lo + hi;
}

EXPORT long long dot(const int *a, const int *b, int n) {
    long long s = 0;
    for (int i = 0; i < n; i++) s += (long long)a[i] * b[i];
    return s;
}

EXPORT size_t length_of(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

EXPORT int compare_strings(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

EXPORT void copy_big(Big *dst, const Big *src) { *dst = *src; }

EXPORT void clear_big(Big *dst) { *dst = (Big){0}; }

EXPORT void copy_bytes(unsigned char *dst, const unsigned char *src, unsigned n) {
    __builtin_memcpy(dst, src, n & 63);
}

EXPORT unsigned bit_tricks(unsigned x, unsigned r) {
    unsigned c = 0, y = x;
    while (y) { c += y & 1; y >>= 1; }
    unsigned rot = (x << (r & 31)) | (x >> ((32 - (r & 31)) & 31));
    return rot ^ (c * 0x9E3779B9u) ^ (x & -x);
}

EXPORT uint32_t crc_loop(const unsigned char *p, int n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (int i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
    }
    return ~crc;
}

EXPORT int divisions(int a, int b, unsigned u) {
    int q = b ? a / b : 0, r = b ? a % b : 0;
    return q + r + a / 7 + (int)(u / 10u) + (int)(u % 3u);
}

EXPORT int state_machine(const char *s) {
    int state = 0, count = 0;
    for (; *s; s++) {
        switch (state) {
        case 0: state = (*s == 'a') ? 1 : 0; break;
        case 1: state = (*s == 'b') ? 2 : (*s == 'a' ? 1 : 0); break;
        case 2: if (*s == 'c') { count++; state = 0; } else state = (*s == 'a') ? 1 : 0; break;
        }
    }
    return count * 10 + state;
}

EXPORT int list_sum(const Node *n, int limit) {
    int s = 0;
    while (n && limit-- > 0) { s += n->value; n = n->next; }
    return s;
}

EXPORT void mat3_mul(int out[9], const int a[9], const int b[9]) {
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++) {
            int s = 0;
            for (int k = 0; k < 3; k++) s += a[i * 3 + k] * b[k * 3 + j];
            out[i * 3 + j] = s;
        }
}

EXPORT double float_mix(const float *f, int n, double x) {
    float avg = 0.0f;
    for (int i = 0; i < n; i++) avg += f[i];
    avg = n ? avg / (float)n : 0.0f;
    return ((x * 3.0 + 2.0) * x - 1.0) + (double)avg + (double)(int)avg;
}

EXPORT int early_exits(int a, int b, int c) {
    if (a < 0) return -1;
    if (b == 0) return a;
    if (c > a + b) return c - b;
    for (int i = 0; i < a; i++) if (i * b == c) return i;
    return 42;
}

EXPORT int alias_pointers(int *a, int *b, int v) { *a = v; *b = v + 1; return *a; }

EXPORT int local_array_index(int i, int v) {
    int arr[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    arr[i & 7] = v;
    return arr[(i + 1) & 7] + arr[i & 7];
}

EXPORT void small_sort(int *p) {
    for (int i = 0; i < 5; i++)
        for (int j = 0; j + 1 < 5 - i; j++)
            if (p[j] > p[j + 1]) { int t = p[j]; p[j] = p[j + 1]; p[j + 1] = t; }
}

EXPORT unsigned flags_update(Flags *f, unsigned m) {
    f->mode = m & 7; f->on = !f->on; f->level = (f->level + m) & 15;
    return f->mode | (f->on << 3) | (f->level << 4);
}

EXPORT long long wide_math(long long a, long long b, int s) {
    return (a * b) + (a >> (s & 31)) + (long long)((unsigned long long)b << (s & 15));
}

EXPORT void saxpy(float *y, const float *x, float a, int n) {
    for (int i = 0; i < n; i++) y[i] = a * x[i] + y[i];
}

EXPORT int binary_search(const int *p, int n, int key) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (p[mid] == key) return mid;
        if (p[mid] < key) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}

EXPORT uint32_t pack_unpack(const unsigned char *b, uint32_t w, unsigned char *out) {
    uint32_t v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    out[0] = (unsigned char)w; out[1] = (unsigned char)(w >> 8);
    out[2] = (unsigned char)(w >> 16); out[3] = (unsigned char)(w >> 24);
    return v ^ w;
}
