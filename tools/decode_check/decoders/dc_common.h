/* G1 decode_check: the flat result every C decoder shim fills (Zydis, XED).
 * Field meanings are the voter-side attributes of design r1-r4 (A1-A12); the fields after
 * target_kind are the raw per-voter evidence of the TBR ISA facts design r3 (layout revision 3).
 * Python reads it through ctypes (decoders.py, DcDecoded): keep the layout in sync. */
#ifndef DC_COMMON_H
#define DC_COMMON_H
#include <stdint.h>
#include <stddef.h>

enum dc_status {
    DC_OK = 0,
    DC_INVALID = 1,      /* the decoder says: not a valid encoding (an A1 vote value); error_name says which */
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
    DC_FLOW_SYSRET = 16,      /* sysret / sysexit (G1 vote value; flow_detail separates them) */
    DC_FLOW_HLT = 17,
    DC_FLOW_XBEGIN = 18,
    DC_FLOW_XABORT = 19,
    DC_FLOW_XEND = 20,
    DC_FLOW_OTHER = 21        /* any other control transfer the shim does not classify */
};

/* the explicit target operand of a near CALL / JMP (Astra impl r4 s3: each voter reports it itself) */
enum dc_target_kind {
    DC_TARGET_UNKNOWN = 0,   /* the decoder could not tell */
    DC_TARGET_NONE = 1,      /* not a near CALL / JMP */
    DC_TARGET_DIRECT = 2,    /* relative branch target */
    DC_TARGET_REGISTER = 3,
    DC_TARGET_MEMORY = 4     /* its effective-address width is address_bits */
};

/* the folded kinds of DC_FLOW_SYSRET kept apart (ISA facts r3 s3 F3); the return form is operand_bits */
enum dc_flow_detail {
    DC_DETAIL_NONE = 0,
    DC_DETAIL_SYSRET = 1,
    DC_DETAIL_SYSEXIT = 2
};

/* priv_flags: the decoder's own privilege attribute, raw (ISA facts r3 s2 capability matrix maps it) */
#define DC_PRIV_ATTRIBUTE 1   /* Zydis ZYDIS_ATTRIB_IS_PRIVILEGED / XED XED_ATTRIBUTE_RING0 */

/* mem_seg_mask: effective segments of the memory operands that access memory (not address-only) */
#define DC_SEG_ES 1
#define DC_SEG_CS 2
#define DC_SEG_SS 4
#define DC_SEG_DS 8
#define DC_SEG_FS 16
#define DC_SEG_GS 32

/* layout revision 4 (ISA facts 2b, design_tbr_isa_ordinary_r3): form evidence and memory accesses */
#define DC_PFX_LOCK 1    /* an effective LOCK prefix */
#define DC_PFX_REP 2     /* an effective REP / REPE (F3) on a string form */
#define DC_PFX_REPNE 4   /* an effective REPNE (F2) on a string form */

enum dc_mem_role {
    DC_ROLE_EXPLICIT = 0,        /* an explicit memory operand (operand_index) */
    DC_ROLE_STACK = 1,           /* implicit, based on RSP / ESP */
    DC_ROLE_STRING_SOURCE = 2,   /* implicit, based on RSI / ESI */
    DC_ROLE_STRING_DEST = 3,     /* implicit, based on RDI / EDI */
    DC_ROLE_OTHER = 4            /* any other implicit access (descriptor tables, XLAT, ...) */
};

#define DC_RFLAGS_MASK 0x3FFFFFu   /* architectural RFLAGS bits 0-21 */

#define DC_MAX_MEM 8
typedef struct {
    int32_t segment;        /* DC_SEG_* bit of its address segment; 0 when the decoder reports none (flat) */
    int32_t read, write;
    int32_t role;           /* enum dc_mem_role */
    int32_t operand_index;  /* explicit operand position, -1 for implicit */
} dc_mem;

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
    int32_t target_kind;       /* enum dc_target_kind (layout revision 2) */
    /* layout revision 3: raw ISA-fact evidence (never part of a G1 vote) */
    int32_t flow_detail;       /* enum dc_flow_detail */
    int32_t priv_flags;        /* DC_PRIV_* */
    int32_t mem_seg_mask;      /* DC_SEG_* */
    int32_t error_code;        /* the decoder's raw error / status code (0 when ok) */
    char error_name[48];       /* its name, e.g. XED "INVALID_FOR_CHIP", Zydis "ILLEGAL_LOCK" */
    char isa_set[48];          /* the decoder's own ISA-set name */
    char extension[48];        /* the decoder's own extension / ISA-extension name */
    char chip[32];             /* the chip profile this decode used ("" = the G1 voter setting) */
    /* layout revision 4: form evidence (2b) */
    char category[32];         /* the decoder's own category name */
    uint32_t rflags_read;      /* RFLAGS bits read, at their architectural positions */
    uint32_t rflags_written;   /* RFLAGS bits written (modified, set, cleared or undefined) */
    int32_t sreg_operand;      /* 1: a segment register is an operand (explicit or hidden); address segments excluded */
    int32_t prefix_flags;      /* DC_PFX_* */
    char op_sig[16];           /* explicit operand kinds: g gpr, m mmx, x xmm, y wider vector, k mask, s segment,
                                  c control / debug, f x87, M memory, A address only, i immediate, r branch target,
                                  ? other */
    int32_t mem_count;         /* memory accesses below (address-only operands excluded) */
    int32_t mem_overflow;      /* 1: more than DC_MAX_MEM accesses */
    dc_mem mem[DC_MAX_MEM];
} dc_decoded;

/* amd: 0 Intel behaviour, 1 AMD behaviour (where the decoder models it) */
int dc_decode(const uint8_t *bytes, size_t length, uint64_t address, int amd, dc_decoded *out);
/* chip: NULL = the G1 voter setting; otherwise a chip profile name (XED only; others return DC_ERROR) */
int dc_decode_ex(const uint8_t *bytes, size_t length, uint64_t address, int amd, const char *chip,
                 dc_decoded *out);
/* XED only: decode under XED_CHIP_ALL with one ISA set removed (single-feature run for split candidates outside
 * the split table, ISA facts r3 s3 F4); others return DC_ERROR */
int dc_decode_without(const uint8_t *bytes, size_t length, uint64_t address, const char *isa_set, dc_decoded *out);
/* ISA-set catalogue for profile digests: name of set `index` (NULL past the last); whether that set is
 * valid for `chip` (1 / 0, -1 unknown chip or not supported by this decoder) */
const char *dc_isa_set_name(int index);
int dc_isa_set_valid_for_chip(int index, const char *chip);
const char *dc_version(void);
int dc_struct_size(void);
/* the layout / ABI revision: fields can fit in old struct padding, so the size alone cannot tell (5: the struct
 * of revision 4, RFLAGS masks limited to bits 0-21, dc_decode_without added) */
#define DC_LAYOUT_REVISION 5
int dc_layout_revision(void);

#endif
