/* G1 decode_check: Intel XED (v2026.08.23) behind dc_common.h.
 * Long mode 64, address width 64, default chip (all); XED models Intel behaviour only, so `amd` must be 0. */
#include <string.h>
#include <stdio.h>
#include "xed/xed-interface.h"
#include "dc_common.h"

static int initialised = 0;

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

int dc_decode(const uint8_t *bytes, size_t length, uint64_t address, int amd, dc_decoded *out) {
    xed_decoded_inst_t x;
    reset(out);
    if (amd) {
        out->status = DC_ERROR;   /* XED does not model AMD behaviour: never a voter there */
        return out->status;
    }
    if (!initialised) {
        xed_tables_init();
        initialised = 1;
    }
    xed_decoded_inst_zero(&x);
    xed_decoded_inst_set_mode(&x, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    xed_error_enum_t error = xed_decode(&x, (const xed_uint8_t *)bytes, (unsigned int)length);
    if (error == XED_ERROR_BUFFER_TOO_SHORT) {
        out->status = DC_NO_MORE_DATA;
        return out->status;
    }
    if (error != XED_ERROR_NONE) {
        out->status = DC_INVALID;
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
    return out->status;
}
