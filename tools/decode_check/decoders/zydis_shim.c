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
    out->target_kind = DC_TARGET_UNKNOWN;
}

int dc_struct_size(void) { return (int)sizeof(dc_decoded); }

int dc_layout_revision(void) { return DC_LAYOUT_REVISION; }

const char *dc_version(void) {
    static char text[64];
    ZyanU64 v = ZydisGetVersion();
    snprintf(text, sizeof(text), "zydis %u.%u.%u.%u", (unsigned)ZYDIS_VERSION_MAJOR(v), (unsigned)ZYDIS_VERSION_MINOR(v),
             (unsigned)ZYDIS_VERSION_PATCH(v), (unsigned)ZYDIS_VERSION_BUILD(v));
    return text;
}

/* chip profiles are an XED facility (ISA facts r3 s3 F4): no ISA-set catalogue here */
const char *dc_isa_set_name(int index) { (void)index; return NULL; }

int dc_isa_set_valid_for_chip(int index, const char *chip) { (void)index; (void)chip; return -1; }

int dc_decode_without(const uint8_t *bytes, size_t length, uint64_t address, const char *isa_set, dc_decoded *out) {
    (void)bytes; (void)length; (void)address; (void)isa_set;
    memset(out, 0, sizeof(*out));
    out->status = DC_ERROR;
    strncpy(out->error_name, "single-feature decode not supported", sizeof(out->error_name) - 1);
    return out->status;
}

static const char *status_name(ZyanStatus status) {
    switch (status) {
    case ZYDIS_STATUS_NO_MORE_DATA: return "NO_MORE_DATA";
    case ZYDIS_STATUS_DECODING_ERROR: return "DECODING_ERROR";
    case ZYDIS_STATUS_INSTRUCTION_TOO_LONG: return "INSTRUCTION_TOO_LONG";
    case ZYDIS_STATUS_BAD_REGISTER: return "BAD_REGISTER";
    case ZYDIS_STATUS_ILLEGAL_LOCK: return "ILLEGAL_LOCK";
    case ZYDIS_STATUS_ILLEGAL_LEGACY_PFX: return "ILLEGAL_LEGACY_PFX";
    case ZYDIS_STATUS_ILLEGAL_REX: return "ILLEGAL_REX";
    case ZYDIS_STATUS_INVALID_MAP: return "INVALID_MAP";
    case ZYDIS_STATUS_MALFORMED_EVEX: return "MALFORMED_EVEX";
    case ZYDIS_STATUS_MALFORMED_MVEX: return "MALFORMED_MVEX";
    case ZYDIS_STATUS_INVALID_MASK: return "INVALID_MASK";
    default: return "OTHER";
    }
}

static int32_t seg_bit(ZydisRegister seg) {
    switch (seg) {
    case ZYDIS_REGISTER_ES: return DC_SEG_ES;
    case ZYDIS_REGISTER_CS: return DC_SEG_CS;
    case ZYDIS_REGISTER_SS: return DC_SEG_SS;
    case ZYDIS_REGISTER_DS: return DC_SEG_DS;
    case ZYDIS_REGISTER_FS: return DC_SEG_FS;
    case ZYDIS_REGISTER_GS: return DC_SEG_GS;
    default: return 0;
    }
}

int dc_decode(const uint8_t *bytes, size_t length, uint64_t address, int amd, dc_decoded *out) {
    return dc_decode_ex(bytes, length, address, amd, NULL, out);
}

static char reg_kind(ZydisRegister reg) {
    switch (ZydisRegisterGetClass(reg)) {
    case ZYDIS_REGCLASS_GPR8: case ZYDIS_REGCLASS_GPR16: case ZYDIS_REGCLASS_GPR32: case ZYDIS_REGCLASS_GPR64:
        return 'g';
    case ZYDIS_REGCLASS_MMX: return 'm';
    case ZYDIS_REGCLASS_XMM: return 'x';
    case ZYDIS_REGCLASS_YMM: case ZYDIS_REGCLASS_ZMM: case ZYDIS_REGCLASS_TMM: return 'y';
    case ZYDIS_REGCLASS_MASK: return 'k';
    case ZYDIS_REGCLASS_SEGMENT: return 's';
    case ZYDIS_REGCLASS_CONTROL: case ZYDIS_REGCLASS_DEBUG: return 'c';
    case ZYDIS_REGCLASS_X87: return 'f';
    default: return '?';
    }
}

static int32_t base_role(ZydisRegister base) {
    switch (base) {
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP: return DC_ROLE_STACK;
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI: return DC_ROLE_STRING_SOURCE;
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI: return DC_ROLE_STRING_DEST;
    default: return DC_ROLE_OTHER;
    }
}

/* layout revision 4: category, RFLAGS read / written, segment-register operands, explicit operand kinds,
 * effective LOCK / REP, memory accesses with role (operands: visible first, then hidden) */
static void fill_form_evidence(const ZydisDecodedInstruction *insn, const ZydisDecodedOperand *ops,
                               dc_decoded *out) {
    const char *category = ZydisCategoryGetString(insn->meta.category);
    if (category) {
        strncpy(out->category, category, sizeof(out->category) - 1);
    }
    if (insn->cpu_flags) {
        out->rflags_read = insn->cpu_flags->tested & DC_RFLAGS_MASK;
        out->rflags_written = (insn->cpu_flags->modified | insn->cpu_flags->set_0 | insn->cpu_flags->set_1
                               | insn->cpu_flags->undefined) & DC_RFLAGS_MASK;
    }
    if (insn->attributes & ZYDIS_ATTRIB_HAS_LOCK) {
        out->prefix_flags |= DC_PFX_LOCK;
    }
    if (insn->attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE)) {
        out->prefix_flags |= DC_PFX_REP;
    }
    if (insn->attributes & ZYDIS_ATTRIB_HAS_REPNE) {
        out->prefix_flags |= DC_PFX_REPNE;
    }
    int sig = 0;
    for (int i = 0; i < insn->operand_count; i++) {
        const ZydisDecodedOperand *op = &ops[i];
        int is_explicit = op->visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
        char kind = '?';
        if (op->type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (ZydisRegisterGetClass(op->reg.value) == ZYDIS_REGCLASS_SEGMENT) {
                out->sreg_operand = 1;
            }
            kind = reg_kind(op->reg.value);
        } else if (op->type == ZYDIS_OPERAND_TYPE_MEMORY) {
            kind = op->mem.type == ZYDIS_MEMOP_TYPE_AGEN ? 'A' : 'M';
            if (op->mem.type != ZYDIS_MEMOP_TYPE_AGEN) {
                if (out->mem_count >= DC_MAX_MEM) {
                    out->mem_overflow = 1;
                } else {
                    dc_mem *m = &out->mem[out->mem_count++];
                    m->segment = seg_bit(op->mem.segment);
                    m->read = (op->actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
                    m->write = (op->actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
                    m->operand_index = is_explicit ? i : -1;
                    m->role = is_explicit ? DC_ROLE_EXPLICIT : base_role(op->mem.base);
                }
            }
        } else if (op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            kind = op->imm.is_relative ? 'r' : 'i';
        } else if (op->type == ZYDIS_OPERAND_TYPE_POINTER) {
            kind = 'r';
        }
        if (is_explicit && sig < (int)sizeof(out->op_sig) - 1) {
            out->op_sig[sig++] = kind;
        }
    }
}

int dc_decode_ex(const uint8_t *bytes, size_t length, uint64_t address, int amd, const char *chip,
                 dc_decoded *out) {
    ZydisDecoder decoder;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    reset(out);
    if (chip) {
        out->status = DC_ERROR;
        strncpy(out->error_name, "chip profiles not supported", sizeof(out->error_name) - 1);
        return out->status;
    }
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        out->status = DC_ERROR;
        return out->status;
    }
    ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_AMD_BRANCHES, amd ? ZYAN_TRUE : ZYAN_FALSE);
    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, bytes, length, &insn, ops);
    if (!ZYAN_SUCCESS(status)) {
        out->error_code = (int32_t)ZYAN_STATUS_CODE(status);
        strncpy(out->error_name, status_name(status), sizeof(out->error_name) - 1);
    }
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
        } else if (insn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
            /* (not ZYDIS_ATTRIB_IS_RELATIVE: it is also set for RIP-relative memory operands) */
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
    if (out->flow == DC_FLOW_CALL_NEAR || out->flow == DC_FLOW_JMP_NEAR) {
        /* the first visible operand is the explicit target (implicit stack operands are hidden) */
        if (!op0) {
            out->target_kind = DC_TARGET_UNKNOWN;
        } else if (op0->type == ZYDIS_OPERAND_TYPE_MEMORY) {
            out->target_kind = DC_TARGET_MEMORY;
        } else if (op0->type == ZYDIS_OPERAND_TYPE_REGISTER) {
            out->target_kind = DC_TARGET_REGISTER;
        } else if (op0->type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op0->imm.is_relative) {
            out->target_kind = DC_TARGET_DIRECT;
        } else {
            out->target_kind = DC_TARGET_UNKNOWN;
        }
    } else {
        out->target_kind = DC_TARGET_NONE;
    }
    if ((out->flow == DC_FLOW_CALL_FAR || out->flow == DC_FLOW_JMP_FAR) && op0
            && (op0->type == ZYDIS_OPERAND_TYPE_REGISTER || op0->type == ZYDIS_OPERAND_TYPE_MEMORY)) {
        out->indirect = 1;
    }
    /* layout revision 3: raw ISA-fact evidence */
    if (insn.mnemonic == ZYDIS_MNEMONIC_SYSEXIT) {
        out->flow_detail = DC_DETAIL_SYSEXIT;
    } else if (insn.mnemonic == ZYDIS_MNEMONIC_SYSRET) {
        out->flow_detail = DC_DETAIL_SYSRET;
    }
    if (insn.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED) {
        out->priv_flags |= DC_PRIV_ATTRIBUTE;
    }
    for (int i = 0; i < insn.operand_count; i++) {
        /* memory accesses only: an address-only operand (lea, AGEN) touches no segment */
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.type != ZYDIS_MEMOP_TYPE_AGEN) {
            out->mem_seg_mask |= seg_bit(ops[i].mem.segment);
        }
    }
    const char *isa_set = ZydisISASetGetString(insn.meta.isa_set);
    const char *isa_ext = ZydisISAExtGetString(insn.meta.isa_ext);
    if (isa_set) {
        strncpy(out->isa_set, isa_set, sizeof(out->isa_set) - 1);
    }
    if (isa_ext) {
        strncpy(out->extension, isa_ext, sizeof(out->extension) - 1);
    }
    fill_form_evidence(&insn, ops, out);
    return out->status;
}
