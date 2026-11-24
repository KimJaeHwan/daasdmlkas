/* G1 decode_check: Zydis (v4.1.1, amalgamated) behind dc_common.h.
 * Long mode 64, stack width 64; AMD behaviour = ZYDIS_DECODER_MODE_AMD_BRANCHES. */
#include <stdio.h>
#include <string.h>
#include "Zydis.h"
#include "dc_common.h"

static void reset(dc_decoded *out) {
    memset(out, 0, sizeof(*out));
    out->disp_offset = -1;
    out->imm_offset[0] = out->imm_offset[1] = -1;
    out->int_vector = -1;
}

int dc_struct_size(void) { return (int)sizeof(dc_decoded); }

const char *dc_version(void) {
    static char text[64];
    ZyanU64 v = ZydisGetVersion();
    snprintf(text, sizeof(text), "zydis %u.%u.%u.%u", (unsigned)ZYDIS_VERSION_MAJOR(v), (unsigned)ZYDIS_VERSION_MINOR(v),
             (unsigned)ZYDIS_VERSION_PATCH(v), (unsigned)ZYDIS_VERSION_BUILD(v));
    return text;
}

int dc_decode(const uint8_t *bytes, size_t length, uint64_t address, int amd, dc_decoded *out) {
    ZydisDecoder decoder;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    reset(out);
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        out->status = DC_ERROR;
        return out->status;
    }
    ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_AMD_BRANCHES, amd ? ZYAN_TRUE : ZYAN_FALSE);
    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, bytes, length, &insn, ops);
    if (status == ZYDIS_STATUS_NO_MORE_DATA) {
        out->status = DC_NO_MORE_DATA;
        return out->status;
    }
    if (!ZYAN_SUCCESS(status)) {
        /* decoding errors (invalid opcode, illegal lock / prefix / REX, too long, bad register ...)
         * are the decoder's statement that the bytes are not a valid encoding */
        out->status = (ZYAN_STATUS_MODULE(status) == ZYAN_MODULE_ZYDIS) ? DC_INVALID : DC_ERROR;
        return out->status;
    }
    out->status = DC_OK;
    out->length = insn.length;
    out->operand_bits = insn.operand_width;
    out->address_bits = insn.address_width;
    out->stack_bits = insn.stack_width;
    out->prefix_count = insn.raw.prefix_count;
    if (insn.raw.disp.size) {
        out->disp_offset = insn.raw.disp.offset;
        out->disp_size = insn.raw.disp.size / 8;
    }
    for (int i = 0; i < 2; i++) {
        if (insn.raw.imm[i].size) {
            out->imm_offset[i] = insn.raw.imm[i].offset;
            out->imm_size[i] = insn.raw.imm[i].size / 8;
        }
    }
    const char *name = ZydisMnemonicGetString(insn.mnemonic);
    if (name) {
        strncpy(out->mnemonic, name, sizeof(out->mnemonic) - 1);
    }
    int far = insn.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR;
    int first_visible = insn.operand_count_visible > 0;
    ZydisDecodedOperand *op0 = first_visible ? &ops[0] : NULL;
    switch (insn.mnemonic) {
    case ZYDIS_MNEMONIC_CALL: out->flow = far ? DC_FLOW_CALL_FAR : DC_FLOW_CALL_NEAR; break;
    case ZYDIS_MNEMONIC_JMP: out->flow = far ? DC_FLOW_JMP_FAR : DC_FLOW_JMP_NEAR; break;
    case ZYDIS_MNEMONIC_RET: out->flow = far ? DC_FLOW_RET_FAR : DC_FLOW_RET_NEAR; break;
    case ZYDIS_MNEMONIC_IRET: case ZYDIS_MNEMONIC_IRETD: case ZYDIS_MNEMONIC_IRETQ: out->flow = DC_FLOW_IRET; break;
    case ZYDIS_MNEMONIC_INT3: out->flow = DC_FLOW_INT3; break;
    case ZYDIS_MNEMONIC_INT: out->flow = DC_FLOW_INT_N; break;
    case ZYDIS_MNEMONIC_INT1: out->flow = DC_FLOW_INT1; break;
    case ZYDIS_MNEMONIC_INTO: out->flow = DC_FLOW_INTO; break;
    case ZYDIS_MNEMONIC_UD0: case ZYDIS_MNEMONIC_UD1: case ZYDIS_MNEMONIC_UD2: out->flow = DC_FLOW_UD; break;
    case ZYDIS_MNEMONIC_SYSCALL: out->flow = DC_FLOW_SYSCALL; break;
    case ZYDIS_MNEMONIC_SYSENTER: out->flow = DC_FLOW_SYSENTER; break;
    case ZYDIS_MNEMONIC_SYSRET: case ZYDIS_MNEMONIC_SYSEXIT: out->flow = DC_FLOW_SYSRET; break;
    case ZYDIS_MNEMONIC_HLT: out->flow = DC_FLOW_HLT; break;
    case ZYDIS_MNEMONIC_XBEGIN: out->flow = DC_FLOW_XBEGIN; break;
    case ZYDIS_MNEMONIC_XABORT: out->flow = DC_FLOW_XABORT; break;
    case ZYDIS_MNEMONIC_XEND: out->flow = DC_FLOW_XEND; break;
    case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE: case ZYDIS_MNEMONIC_LOOPNE:
    case ZYDIS_MNEMONIC_JCXZ: case ZYDIS_MNEMONIC_JECXZ: case ZYDIS_MNEMONIC_JRCXZ:
        out->flow = DC_FLOW_JCC;
        out->counter = 1;
        break;
    default:
        if (insn.meta.category == ZYDIS_CATEGORY_COND_BR) {
            out->flow = DC_FLOW_JCC;
        } else if (insn.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
            out->flow = DC_FLOW_OTHER;
        } else {
            out->flow = DC_FLOW_NONE;
        }
    }
    if (out->flow == DC_FLOW_INT_N && op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        out->int_vector = (int32_t)op0->imm.value.u;
    }
    if (out->flow == DC_FLOW_RET_NEAR || out->flow == DC_FLOW_RET_FAR) {
        if (op0 && op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            out->ret_imm = 1;
            out->ret_imm_value = (int32_t)op0->imm.value.u;
        }
    }
    int near_transfer = out->flow == DC_FLOW_CALL_NEAR || out->flow == DC_FLOW_JMP_NEAR || out->flow == DC_FLOW_JCC
                        || out->flow == DC_FLOW_XBEGIN;
    if (near_transfer && op0) {
        out->target_ip_bits = insn.operand_width;
        if (op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op0->imm.is_relative) {
            ZyanU64 target = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, op0, address, &target))) {
                out->has_target = 1;
                out->target = target;
            }
            out->encoded_disp_bits = insn.raw.imm[0].size;
        } else if (op0->type == ZYDIS_OPERAND_TYPE_REGISTER || op0->type == ZYDIS_OPERAND_TYPE_MEMORY) {
            out->indirect = 1;
        }
    }
    if ((out->flow == DC_FLOW_CALL_FAR || out->flow == DC_FLOW_JMP_FAR) && op0
            && (op0->type == ZYDIS_OPERAND_TYPE_REGISTER || op0->type == ZYDIS_OPERAND_TYPE_MEMORY)) {
        out->indirect = 1;
    }
    return out->status;
}
