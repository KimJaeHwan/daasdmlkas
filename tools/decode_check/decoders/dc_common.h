/* G1 decode_check: the flat result every C decoder shim fills (Zydis, XED).
 * Field meanings are the voter-side attributes of design r1-r4 (A1-A12).
 * Python reads it through ctypes (decoders.py, DcDecoded): keep the layout in sync. */
#ifndef DC_COMMON_H
#define DC_COMMON_H
#include <stdint.h>
#include <stddef.h>

enum dc_status {
    DC_OK = 0,
    DC_INVALID = 1,      /* the decoder says: not a valid encoding (an A1 vote value) */
    DC_NO_MORE_DATA = 2, /* needs more bytes than given (a failure: insufficient bytes) */
    DC_ERROR = 3         /* any other decoder error (a failure) */
};

/* normalised flow kind (the same enum for every voter) */
enum dc_flow {
    DC_FLOW_NONE = 0,
    DC_FLOW_CALL_NEAR = 1,
    DC_FLOW_CALL_FAR = 2,
    DC_FLOW_JMP_NEAR = 3,
    DC_FLOW_JMP_FAR = 4,
    DC_FLOW_JCC = 5,          /* conditional near branch, loop / jcxz included (see counter) */
    DC_FLOW_RET_NEAR = 6,
    DC_FLOW_RET_FAR = 7,
    DC_FLOW_IRET = 8,
    DC_FLOW_INT3 = 9,
    DC_FLOW_INT_N = 10,
    DC_FLOW_INT1 = 11,
    DC_FLOW_INTO = 12,
    DC_FLOW_UD = 13,          /* ud0 / ud1 / ud2 */
    DC_FLOW_SYSCALL = 14,
    DC_FLOW_SYSENTER = 15,
    DC_FLOW_SYSRET = 16,      /* sysret / sysexit */
    DC_FLOW_HLT = 17,
    DC_FLOW_XBEGIN = 18,
    DC_FLOW_XABORT = 19,
    DC_FLOW_XEND = 20,
    DC_FLOW_OTHER = 21        /* any other control transfer the shim does not classify */
};

typedef struct {
    int32_t status;
    int32_t length;
    int32_t flow;              /* enum dc_flow */
    int32_t indirect;          /* 1: register / memory target */
    int32_t has_target;        /* 1: a direct target VA below */
    int32_t counter;           /* 1: loop / jcxz family (counter register selected by address size) */
    uint64_t target;           /* direct target VA as this decoder computes it */
    int32_t target_ip_bits;    /* operand size of the target IP (16 / 32 / 64), 0 when not a near transfer */
    int32_t encoded_disp_bits; /* width of the encoded relative displacement (8 / 16 / 32), 0 if none */
    int32_t operand_bits;      /* effective operand size */
    int32_t address_bits;      /* effective address size */
    int32_t stack_bits;        /* stack width */
    int32_t ret_imm;           /* 1: ret imm16 */
    int32_t ret_imm_value;
    int32_t int_vector;        /* int n: n; else -1 */
    int32_t prefix_count;      /* legacy + REX prefix bytes */
    int32_t disp_offset, disp_size;     /* memory or branch displacement field, -1 / 0 if none */
    int32_t imm_offset[2], imm_size[2]; /* immediate fields, -1 / 0 if none */
    char mnemonic[32];
} dc_decoded;

/* amd: 0 Intel behaviour, 1 AMD behaviour (where the decoder models it) */
int dc_decode(const uint8_t *bytes, size_t length, uint64_t address, int amd, dc_decoded *out);
const char *dc_version(void);
int dc_struct_size(void);

#endif
