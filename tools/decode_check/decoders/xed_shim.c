/* G1 decode_check: Intel XED (v2026.08.23) behind dc_common.h.
 * Long mode 64, address width 64; XED models Intel behaviour only, so `amd` must be 0.
 * The G1 voter setting leaves the input chip unset (XED_CHIP_INVALID). Measured on v2026.08.23: then XED
 * accepts every ISA set but decodes feature-dependent encodings under their legacy meaning (F3 0F BC BSF,
 * F3 90 NOP, F3 0F 1E FA NOP). dc_decode_ex(chip) decodes the same bytes under a named chip profile
 * (ISA facts r3 s3 F4). mem_seg_mask: in 64-bit mode XED reports a segment only for an FS / GS
 * override (the flat default segments come back as no register), so only its FS / GS bits are evidence. */
#include <string.h>
#include <stdio.h>
#include "xed/xed-interface.h"
#include "dc_common.h"

static int initialised = 0;   /* (xed_tables_init once; ctypes calls are serial) */

static void reset(dc_decoded *out) {
    memset(out, 0, sizeof(*out));
    out->disp_offset = -1;
    out->imm_offset[0] = out->imm_offset[1] = -1;
    out->int_vector = -1;
}

int dc_layout_revision(void) { return DC_LAYOUT_REVISION; }

int dc_struct_size(void) { return (int)sizeof(dc_decoded); }

const char *dc_version(void) {
    static char text[96];
    snprintf(text, sizeof(text), "xed %s", xed_get_version());
    return text;
}

/* the first EXPLICIT operand of a near CALL / JMP: MEM0 memory, REG0 register, RELBR direct
 * (implicit stack / IP operands are skipped) */
static int32_t explicit_target_kind(const xed_decoded_inst_t *x) {
    const xed_inst_t *inst = xed_decoded_inst_inst(x);
    unsigned int count = xed_inst_noperands(inst);
    for (unsigned int i = 0; i < count; i++) {
        const xed_operand_t *operand = xed_inst_operand(inst, i);
        if (xed_operand_operand_visibility(operand) != XED_OPVIS_EXPLICIT) {
            continue;
        }
        switch (xed_operand_name(operand)) {
        case XED_OPERAND_MEM0: return DC_TARGET_MEMORY;
        case XED_OPERAND_REG0: return DC_TARGET_REGISTER;
        case XED_OPERAND_RELBR: return DC_TARGET_DIRECT;
        default: return DC_TARGET_UNKNOWN;
        }
    }
    return DC_TARGET_UNKNOWN;
}

static int first_operand_name(const xed_decoded_inst_t *x) {
    const xed_inst_t *inst = xed_decoded_inst_inst(x);
    if (xed_inst_noperands(inst) == 0) {
        return XED_OPERAND_INVALID;
    }
    return xed_operand_name(xed_inst_operand(inst, 0));
}

static void init_tables(void) {
    if (!initialised) {
        xed_tables_init();
        initialised = 1;
    }
}

/* a chip profile name ("ALL", "P4PRESCOTT_NOLAHF", ...) -> its enum; XED_CHIP_INVALID if unknown */
static xed_chip_enum_t chip_by_name(const char *name) {
    xed_chip_enum_t chip = str2xed_chip_enum_t(name);
    return chip == XED_CHIP_LAST ? XED_CHIP_INVALID : chip;
}

const char *dc_isa_set_name(int index) {
    init_tables();
    if (index <= (int)XED_ISA_SET_INVALID || index >= (int)XED_ISA_SET_LAST) {
        return NULL;
    }
    return xed_isa_set_enum_t2str((xed_isa_set_enum_t)index);
}

int dc_isa_set_valid_for_chip(int index, const char *chip_name) {
    init_tables();
    xed_chip_enum_t chip = chip_by_name(chip_name);
    if (chip == XED_CHIP_INVALID || index <= (int)XED_ISA_SET_INVALID || index >= (int)XED_ISA_SET_LAST) {
        return -1;
    }
    return xed_isa_set_is_valid_for_chip((xed_isa_set_enum_t)index, chip) ? 1 : 0;
}

static int32_t seg_bit(xed_reg_enum_t seg) {
    switch (seg) {
    case XED_REG_ES: return DC_SEG_ES;
    case XED_REG_CS: return DC_SEG_CS;
    case XED_REG_SS: return DC_SEG_SS;
    case XED_REG_DS: return DC_SEG_DS;
    case XED_REG_FS: return DC_SEG_FS;
    case XED_REG_GS: return DC_SEG_GS;
    default: return 0;
    }
}

int dc_decode(const uint8_t *bytes, size_t length, uint64_t address, int amd, dc_decoded *out) {
    return dc_decode_ex(bytes, length, address, amd, NULL, out);
}

int dc_decode_ex(const uint8_t *bytes, size_t length, uint64_t address, int amd, const char *chip_name,
                 dc_decoded *out) {
    xed_decoded_inst_t x;
    reset(out);
    if (amd) {
        out->status = DC_ERROR;   /* XED does not model AMD behaviour: never a voter there */
        return out->status;
    }
    init_tables();
    xed_decoded_inst_zero(&x);
    xed_decoded_inst_set_mode(&x, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    if (chip_name) {
        xed_chip_enum_t chip = chip_by_name(chip_name);
        if (chip == XED_CHIP_INVALID) {
            out->status = DC_ERROR;
            strncpy(out->error_name, "unknown chip profile", sizeof(out->error_name) - 1);
            return out->status;
        }
        xed_decoded_inst_set_input_chip(&x, chip);
        strncpy(out->chip, xed_chip_enum_t2str(chip), sizeof(out->chip) - 1);
    }
    xed_error_enum_t error = xed_decode(&x, (const xed_uint8_t *)bytes, (unsigned int)length);
    out->error_code = (int32_t)error;
    if (error != XED_ERROR_NONE) {
        strncpy(out->error_name, xed_error_enum_t2str(error), sizeof(out->error_name) - 1);
    }
    if (error == XED_ERROR_BUFFER_TOO_SHORT) {
        out->status = DC_NO_MORE_DATA;
        return out->status;
    }
    if (error != XED_ERROR_NONE) {
        out->status = DC_INVALID;   /* INVALID_FOR_CHIP stays apart in error_name (F1) */
        return out->status;
    }
    out->status = DC_OK;
    out->length = (int32_t)xed_decoded_inst_get_length(&x);
    const xed_operand_values_t *values = xed_decoded_inst_operands_const(&x);
    out->operand_bits = (int32_t)xed_operand_values_get_effective_operand_width(values);
    out->address_bits = (int32_t)xed_operand_values_get_effective_address_width(values);
    out->stack_bits = (int32_t)xed_operand_values_get_stack_address_width(values);
    out->prefix_count = (int32_t)xed3_operand_get_nprefixes(&x);
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&x);
    strncpy(out->mnemonic, xed_iclass_enum_t2str(iclass), sizeof(out->mnemonic) - 1);
    xed_category_enum_t category = xed_decoded_inst_get_category(&x);

    unsigned int brdisp_width = xed_decoded_inst_get_branch_displacement_width(&x);
    unsigned int mem_disp_width = xed_decoded_inst_get_memory_displacement_width(&x, 0);
    unsigned int disp_width = brdisp_width ? brdisp_width : mem_disp_width;
    if (disp_width) {
        out->disp_offset = (int32_t)xed3_operand_get_pos_disp(&x);
        out->disp_size = (int32_t)disp_width;
    }
    unsigned int imm_width = xed_decoded_inst_get_immediate_width(&x);
    if (imm_width) {
        out->imm_offset[0] = (int32_t)xed3_operand_get_pos_imm(&x);
        out->imm_size[0] = (int32_t)imm_width;
    }
    if (xed3_operand_get_imm1(&x) || xed_decoded_inst_get_second_immediate(&x)) {
        out->imm_offset[1] = (int32_t)xed3_operand_get_pos_imm1(&x);
        out->imm_size[1] = 1;
    }

    int op0 = first_operand_name(&x);
    int is_far = op0 == XED_OPERAND_PTR || iclass == XED_ICLASS_CALL_FAR || iclass == XED_ICLASS_JMP_FAR
                 || iclass == XED_ICLASS_RET_FAR;
    switch (iclass) {
    case XED_ICLASS_CALL_NEAR: out->flow = DC_FLOW_CALL_NEAR; break;
    case XED_ICLASS_CALL_FAR: out->flow = DC_FLOW_CALL_FAR; break;
    case XED_ICLASS_JMP: out->flow = DC_FLOW_JMP_NEAR; break;
    case XED_ICLASS_JMP_FAR: out->flow = DC_FLOW_JMP_FAR; break;
    case XED_ICLASS_RET_NEAR: out->flow = DC_FLOW_RET_NEAR; break;
    case XED_ICLASS_RET_FAR: out->flow = DC_FLOW_RET_FAR; break;
    case XED_ICLASS_IRET: case XED_ICLASS_IRETD: case XED_ICLASS_IRETQ: out->flow = DC_FLOW_IRET; break;
    case XED_ICLASS_INT3: out->flow = DC_FLOW_INT3; break;
    case XED_ICLASS_INT: out->flow = DC_FLOW_INT_N; break;
    case XED_ICLASS_INT1: out->flow = DC_FLOW_INT1; break;
    case XED_ICLASS_INTO: out->flow = DC_FLOW_INTO; break;
    case XED_ICLASS_UD0: case XED_ICLASS_UD1: case XED_ICLASS_UD2: out->flow = DC_FLOW_UD; break;
    case XED_ICLASS_SYSCALL: out->flow = DC_FLOW_SYSCALL; break;
    case XED_ICLASS_SYSENTER: out->flow = DC_FLOW_SYSENTER; break;
    case XED_ICLASS_SYSRET: case XED_ICLASS_SYSRET64: case XED_ICLASS_SYSEXIT: out->flow = DC_FLOW_SYSRET; break;
    case XED_ICLASS_HLT: out->flow = DC_FLOW_HLT; break;
    case XED_ICLASS_XBEGIN: out->flow = DC_FLOW_XBEGIN; break;
    case XED_ICLASS_XABORT: out->flow = DC_FLOW_XABORT; break;
    case XED_ICLASS_XEND: out->flow = DC_FLOW_XEND; break;
    case XED_ICLASS_LOOP: case XED_ICLASS_LOOPE: case XED_ICLASS_LOOPNE:
    case XED_ICLASS_JCXZ: case XED_ICLASS_JECXZ: case XED_ICLASS_JRCXZ:
        out->flow = DC_FLOW_JCC;
        out->counter = 1;
        break;
    default:
        if (category == XED_CATEGORY_COND_BR) {
            out->flow = DC_FLOW_JCC;
        } else if (brdisp_width) {
            out->flow = DC_FLOW_OTHER;
        } else {
            out->flow = DC_FLOW_NONE;
        }
    }
    (void)is_far;
    if (out->flow == DC_FLOW_INT_N) {
        out->int_vector = (int32_t)xed_decoded_inst_get_unsigned_immediate(&x);
    }
    if ((out->flow == DC_FLOW_RET_NEAR || out->flow == DC_FLOW_RET_FAR) && imm_width) {
        out->ret_imm = 1;
        out->ret_imm_value = (int32_t)xed_decoded_inst_get_unsigned_immediate(&x);
    }
    int near_transfer = out->flow == DC_FLOW_CALL_NEAR || out->flow == DC_FLOW_JMP_NEAR || out->flow == DC_FLOW_JCC
                        || out->flow == DC_FLOW_XBEGIN;
    if (near_transfer) {
        out->target_ip_bits = out->operand_bits;
        if (brdisp_width) {
            /* next IP + displacement, truncated to the effective operand width (XED's Intel view) */
            uint64_t next = address + (uint64_t)out->length;
            uint64_t target = next + (uint64_t)xed_decoded_inst_get_branch_displacement(&x);
            if (out->operand_bits == 16) {
                target &= 0xFFFFull;
            } else if (out->operand_bits == 32) {
                target &= 0xFFFFFFFFull;
            }
            out->has_target = 1;
            out->target = target;
            out->encoded_disp_bits = (int32_t)(brdisp_width * 8);
        } else {
            out->indirect = 1;
        }
    }
    out->target_kind = (out->flow == DC_FLOW_CALL_NEAR || out->flow == DC_FLOW_JMP_NEAR)
                       ? explicit_target_kind(&x) : DC_TARGET_NONE;
    if ((out->flow == DC_FLOW_CALL_FAR || out->flow == DC_FLOW_JMP_FAR) && op0 != XED_OPERAND_PTR) {
        out->indirect = 1;
    }
    /* layout revision 3: raw ISA-fact evidence */
    if (iclass == XED_ICLASS_SYSEXIT) {
        out->flow_detail = DC_DETAIL_SYSEXIT;
    } else if (out->flow == DC_FLOW_SYSRET) {
        out->flow_detail = DC_DETAIL_SYSRET;
    }
    if (xed_decoded_inst_get_attribute(&x, XED_ATTRIBUTE_RING0)) {
        out->priv_flags |= DC_PRIV_ATTRIBUTE;
    }
    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&x);
    for (unsigned int i = 0; i < memops; i++) {
        if (xed_decoded_inst_mem_read(&x, i) || xed_decoded_inst_mem_written(&x, i)) {
            out->mem_seg_mask |= seg_bit(xed_decoded_inst_get_seg_reg(&x, i));
        }
    }
    strncpy(out->isa_set, xed_isa_set_enum_t2str(xed_decoded_inst_get_isa_set(&x)), sizeof(out->isa_set) - 1);
    strncpy(out->extension, xed_extension_enum_t2str(xed_decoded_inst_get_extension(&x)),
            sizeof(out->extension) - 1);
    return out->status;
}
