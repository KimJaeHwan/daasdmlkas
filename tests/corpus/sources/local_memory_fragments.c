/* Compile and extract the original STORE/LOADs; no alias or ABI engine model. */
typedef unsigned long long u64;
typedef unsigned char u8;
#define EXPORTED __attribute__((noinline, visibility("default")))

EXPORTED u64 local_byte_patch(volatile u64 *p, u64 value, u8 patch)
{
    *p = value;
    ((volatile u8 *)p)[3] = patch;
    return *p;
}

EXPORTED u64 local_conditional_patch(volatile u64 *p, u64 value, u8 patch, int flag)
{
    *p = value;
    if (flag)
        ((volatile u8 *)p)[3] = patch;
    return *p;
}

EXPORTED u64 local_unknown_patch(volatile u64 *p, u64 value, volatile u8 *q, u8 patch)
{
    *p = value;
    *q = patch;
    return *p;
}
