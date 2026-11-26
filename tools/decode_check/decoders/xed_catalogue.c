/* TBR ISA facts 2b: dump the pinned XED instruction table for the ordinary-form generator
 * (tools/decode_check/isa_ordinary_gen.py). One line per xed_inst_t, tab separated:
 *   iclass category extension isa_set ring0 exception explicit_kinds sreg iform
 * explicit_kinds: the explicit operands' kinds (g m x y k s c f M A i r ?), as in dc_common.h op_sig;
 * sreg: 1 when any operand (explicit or not) is a segment register. Built by build_decoders.sh. */
#include <stdio.h>
#include <string.h>
#include "xed/xed-interface.h"

static char kind_of_reg(xed_reg_enum_t reg) {
    switch (xed_reg_class(reg)) {
    case XED_REG_CLASS_GPR: return 'g';
    case XED_REG_CLASS_MMX: return 'm';
    case XED_REG_CLASS_XMM: return 'x';
    case XED_REG_CLASS_YMM: case XED_REG_CLASS_ZMM: return 'y';
    case XED_REG_CLASS_MASK: return 'k';
    case XED_REG_CLASS_SR: return 's';
    case XED_REG_CLASS_CR: case XED_REG_CLASS_DR: return 'c';
    case XED_REG_CLASS_X87: return 'f';
    default: return '?';
    }
}

/* a register operand chosen by a nonterminal: its kind from the nonterminal's name */
static char kind_of_nonterminal(const char *nt) {
    if (strstr(nt, "XMM")) return 'x';
    if (strstr(nt, "YMM") || strstr(nt, "ZMM") || strstr(nt, "TMM")) return 'y';
    if (strstr(nt, "MMX")) return 'm';
    if (strstr(nt, "MASK")) return 'k';
    if (strstr(nt, "SEG")) return 's';
    if (strstr(nt, "CR_") || strstr(nt, "DR_")) return 'c';
    if (strstr(nt, "X87")) return 'f';
    if (strstr(nt, "GPR") || strstr(nt, "OrAX") || strstr(nt, "OrBX") || strstr(nt, "OrCX") || strstr(nt, "OrDX")
            || strstr(nt, "OrSP") || strstr(nt, "OrBP") || strstr(nt, "OrSI") || strstr(nt, "OrDI")
            || strstr(nt, "rAX") || strstr(nt, "rBX") || strstr(nt, "rCX") || strstr(nt, "rDX")) return 'g';
    return '?';
}

int main(void) {
    xed_tables_init();
    const xed_inst_t *base = xed_inst_table_base();
    for (unsigned int i = 0; i < XED_MAX_INST_TABLE_NODES; i++) {
        const xed_inst_t *p = base + i;
        xed_iclass_enum_t iclass = xed_inst_iclass(p);
        if (iclass == XED_ICLASS_INVALID) {
            continue;
        }
        char kinds[24] = {0};
        int n = 0, sreg = 0;
        for (unsigned int j = 0; j < xed_inst_noperands(p); j++) {
            const xed_operand_t *op = xed_inst_operand(p, j);
            xed_operand_enum_t name = xed_operand_name(op);
            char kind = '?';
            if (xed_operand_is_register(name)) {
                xed_operand_type_enum_t type = xed_operand_type(op);
                if (type == XED_OPERAND_TYPE_REG) {
                    kind = kind_of_reg(xed_operand_reg(op));
                } else {
                    kind = kind_of_nonterminal(xed_nonterminal_enum_t2str(xed_operand_nonterminal_name(op)));
                }
                if (kind == 's') {
                    sreg = 1;
                }
            } else if (name == XED_OPERAND_MEM0 || name == XED_OPERAND_MEM1) {
                kind = 'M';
            } else if (name == XED_OPERAND_AGEN) {
                kind = 'A';
            } else if (name == XED_OPERAND_IMM0 || name == XED_OPERAND_IMM1 || name == XED_OPERAND_IMM0SIGNED) {
                kind = 'i';
            } else if (name == XED_OPERAND_RELBR || name == XED_OPERAND_PTR) {
                kind = 'r';
            }
            if (xed_operand_operand_visibility(op) == XED_OPVIS_EXPLICIT && n < (int)sizeof(kinds) - 1) {
                kinds[n++] = kind;
            }
        }
        printf("%s\t%s\t%s\t%s\t%d\t%s\t%s\t%d\t%s\n", xed_iclass_enum_t2str(iclass),
               xed_category_enum_t2str(xed_inst_category(p)), xed_extension_enum_t2str(xed_inst_extension(p)),
               xed_isa_set_enum_t2str(xed_inst_isa_set(p)), xed_inst_get_attribute(p, XED_ATTRIBUTE_RING0) ? 1 : 0,
               xed_exception_enum_t2str(xed_inst_exception(p)), n ? kinds : "-", sreg,
               xed_iform_enum_t2str(xed_inst_iform_enum(p)));
    }
    return 0;
}
