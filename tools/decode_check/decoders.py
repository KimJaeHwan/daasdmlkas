"""The three pinned voters of G1 decode_check behind one interface (design r0 s4,
r1 s5, r3 s4, r4 s3): iced-x86 (Python package), Zydis and XED (C shims through
ctypes, dc_common.h). Every result names its decoder, version and mode.

``decode(voter, data, address, amd) -> Decoded``; ``Decoded.status`` is ``ok``,
``invalid`` (a vote value: not a valid encoding), ``no_more_data`` or ``error``
(failures: the attribute is unobserved). The decoders live outside the engine
venv (``build_decoders.sh``: $G1_DECODERS, default /root/g1_decoders).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
import os
from pathlib import Path
import sys

DECODERS = Path(os.environ.get("G1_DECODERS", "/root/g1_decoders"))
FLOWS = ("none", "call_near", "call_far", "jmp_near", "jmp_far", "jcc", "ret_near", "ret_far", "iret", "int3",
         "int_n", "int1", "into", "ud", "syscall", "sysenter", "sysret", "hlt", "xbegin", "xabort", "xend", "other")
STATUSES = ("ok", "invalid", "no_more_data", "error")
TARGET_KINDS = ("unknown", "none", "direct", "register", "memory")   # (enum dc_target_kind)
LAYOUT_REVISION = 6
MAX_LENGTH = 15
FLOW_DETAILS = ("none", "sysret", "sysexit")                     # (enum dc_flow_detail)
SEGMENTS = (("es", 1), ("cs", 2), ("ss", 4), ("ds", 8), ("fs", 16), ("gs", 32))   # (DC_SEG_*)
PRIV_ATTRIBUTE = 1                                                 # (DC_PRIV_ATTRIBUTE)
PFX_LOCK, PFX_REP, PFX_REPNE = 1, 2, 4                             # (DC_PFX_*)
MEM_ROLES = ("explicit", "stack", "string_source", "string_dest", "other")   # (enum dc_mem_role)
MAX_MEM = 8                                                        # (DC_MAX_MEM)
# RFLAGS bit positions (architectural)
RFLAGS_BITS = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "TF": 8, "IF": 9, "DF": 10, "OF": 11, "IOPL": 12,
               "NT": 14, "RF": 16, "VM": 17, "AC": 18, "VIF": 19, "VIP": 20, "ID": 21}


@dataclass(frozen=True)
class Decoded:
    voter: str
    version: str
    amd: bool
    status: str
    length: int = 0
    flow: str = "none"
    indirect: bool = False
    target: int | None = None
    counter: bool = False
    target_ip_bits: int = 0
    encoded_disp_bits: int = 0
    operand_bits: int = 0
    address_bits: int = 0
    stack_bits: int = 0
    ret_imm: int | None = None
    int_vector: int | None = None
    value_fields: tuple = ()          # ((offset, size), ...) of displacement / immediate fields
    mnemonic: str = ""
    target_derivation: str = ""       # "decoder" | "computed: next IP + displacement at the operand width"
    target_kind: str = "unknown"      # near CALL / JMP explicit target: memory / register / direct / none / unknown
    # raw ISA-fact evidence (ISA facts r3; layout revision 3): never part of a G1 vote nor of as_json
    extra: dict = field(default_factory=dict, compare=False)

    def as_json(self) -> dict:
        out = {name: getattr(self, name) for name in (
            "voter", "version", "amd", "status", "length", "flow", "indirect", "target", "counter", "target_ip_bits",
            "encoded_disp_bits", "operand_bits", "address_bits", "stack_bits", "ret_imm", "int_vector",
            "mnemonic", "target_derivation", "target_kind")}
        out["value_fields"] = [list(item) for item in self.value_fields]
        return out


# -- C shims ---------------------------------------------------------------------------------

class DcMem(ctypes.Structure):
    _fields_ = [("segment", ctypes.c_int32), ("read", ctypes.c_int32), ("write", ctypes.c_int32),
                ("role", ctypes.c_int32), ("operand_index", ctypes.c_int32),
                ("cond_read", ctypes.c_int32), ("cond_write", ctypes.c_int32)]   # (revision 6)


class DcDecoded(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int32), ("length", ctypes.c_int32), ("flow", ctypes.c_int32),
        ("indirect", ctypes.c_int32), ("has_target", ctypes.c_int32), ("counter", ctypes.c_int32),
        ("target", ctypes.c_uint64), ("target_ip_bits", ctypes.c_int32), ("encoded_disp_bits", ctypes.c_int32),
        ("operand_bits", ctypes.c_int32), ("address_bits", ctypes.c_int32), ("stack_bits", ctypes.c_int32),
        ("ret_imm", ctypes.c_int32), ("ret_imm_value", ctypes.c_int32), ("int_vector", ctypes.c_int32),
        ("prefix_count", ctypes.c_int32), ("disp_offset", ctypes.c_int32), ("disp_size", ctypes.c_int32),
        ("imm_offset", ctypes.c_int32 * 2), ("imm_size", ctypes.c_int32 * 2), ("mnemonic", ctypes.c_char * 32),
        ("target_kind", ctypes.c_int32),   # (layout revision 2: an older library fails the size check)
        # layout revision 3: raw ISA-fact evidence
        ("flow_detail", ctypes.c_int32), ("priv_flags", ctypes.c_int32), ("mem_seg_mask", ctypes.c_int32),
        ("error_code", ctypes.c_int32), ("error_name", ctypes.c_char * 48), ("isa_set", ctypes.c_char * 48),
        ("extension", ctypes.c_char * 48), ("chip", ctypes.c_char * 32),
        # layout revision 4: form evidence (2b)
        ("category", ctypes.c_char * 32), ("rflags_read", ctypes.c_uint32), ("rflags_written", ctypes.c_uint32),
        ("sreg_operand", ctypes.c_int32), ("prefix_flags", ctypes.c_int32), ("op_sig", ctypes.c_char * 16),
        ("mem_count", ctypes.c_int32), ("mem_overflow", ctypes.c_int32), ("mem", DcMem * 8),
        ("iform", ctypes.c_char * 64),     # (revision 6)
    ]


def _text(raw: bytes) -> str:
    return raw.decode(errors="replace")


def _shim_extra(out: DcDecoded) -> dict:
    """The raw per-voter ISA-fact evidence of one shim decode (ISA facts r3 s1 layer 1)."""
    extra = {"error": _text(out.error_name), "error_code": out.error_code, "chip": _text(out.chip)}
    if out.status == 0:
        extra.update({
            "flow_detail": FLOW_DETAILS[out.flow_detail] if 0 <= out.flow_detail < len(FLOW_DETAILS) else "none",
            "privileged_attribute": bool(out.priv_flags & PRIV_ATTRIBUTE),
            "mem_segments": [name for name, bit in SEGMENTS if out.mem_seg_mask & bit],
            "isa_set": _text(out.isa_set), "extension": _text(out.extension),
            # layout revision 4
            "category": _text(out.category), "rflags_read": out.rflags_read, "rflags_written": out.rflags_written,
            "sreg_operand": bool(out.sreg_operand), "lock": bool(out.prefix_flags & PFX_LOCK),
            "rep": "rep" if out.prefix_flags & PFX_REP else ("repne" if out.prefix_flags & PFX_REPNE else ""),
            "op_sig": _text(out.op_sig), "mem_overflow": bool(out.mem_overflow), "iform": _text(out.iform),
            "memory_complete": not out.mem_overflow,
            "memory": [_mem(out.mem[i], out.prefix_flags) for i in range(min(out.mem_count, MAX_MEM))]})
    return extra


def _mem(m, prefix_flags: int) -> dict:
    role = MEM_ROLES[m.role] if 0 <= m.role < len(MEM_ROLES) else "other"
    # a REP-prefixed string access does not happen when the count register is 0 (2b r3 s6); other conditional
    # accesses (MASKMOVDQU's mask, CMOVcc's load) come from the decoder per read / write (revision 6)
    rep = bool(prefix_flags & (PFX_REP | PFX_REPNE)) and role in ("string_source", "string_dest")
    cond_read = bool(m.cond_read) or (rep and bool(m.read))
    cond_write = bool(m.cond_write) or (rep and bool(m.write))
    return {"segment": next((name for name, bit in SEGMENTS if m.segment == bit), ""), "read": bool(m.read),
            "write": bool(m.write), "role": role, "cond_read": cond_read, "cond_write": cond_write,
            "conditional": cond_read or cond_write,
            "operand_index": m.operand_index if m.operand_index >= 0 else None}


class _Shim:
    def __init__(self, name: str, library: Path, derivation: str) -> None:
        self.name = name
        self.lib = ctypes.CDLL(str(library))
        self.lib.dc_decode.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_int,
                                       ctypes.POINTER(DcDecoded)]
        self.lib.dc_decode.restype = ctypes.c_int
        self.lib.dc_decode_ex.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_int,
                                          ctypes.c_char_p, ctypes.POINTER(DcDecoded)]
        self.lib.dc_decode_ex.restype = ctypes.c_int
        self.lib.dc_decode_without.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_char_p,
                                               ctypes.POINTER(DcDecoded)]
        self.lib.dc_decode_without.restype = ctypes.c_int
        self.lib.dc_isa_set_name.argtypes = [ctypes.c_int]
        self.lib.dc_isa_set_name.restype = ctypes.c_char_p
        self.lib.dc_isa_set_valid_for_chip.argtypes = [ctypes.c_int, ctypes.c_char_p]
        self.lib.dc_isa_set_valid_for_chip.restype = ctypes.c_int
        self.lib.dc_version.restype = ctypes.c_char_p
        self.lib.dc_struct_size.restype = ctypes.c_int
        if self.lib.dc_struct_size() != ctypes.sizeof(DcDecoded):
            raise RuntimeError(f"{name}: dc_decoded layout differs from decoders.DcDecoded")
        revision = getattr(self.lib, "dc_layout_revision", None)
        if revision is None or revision() != LAYOUT_REVISION:
            raise RuntimeError(f"{name}: dc_decoded layout revision is not {LAYOUT_REVISION} (rebuild the shims: "
                               "build_decoders.sh)")
        self.version = self.lib.dc_version().decode()
        self.derivation = derivation

    def decode(self, data: bytes, address: int, amd: bool, chip: str | None = None,
               without: str | None = None) -> Decoded:
        """chip None: the G1 voter setting; else a chip profile (XED only, ISA facts r3 s3 F4). without: decode
        under XED_CHIP_ALL with that one ISA set removed (XED only: single-feature run)."""
        out = DcDecoded()
        if without:
            self.lib.dc_decode_without(data, len(data), address, without.encode(), ctypes.byref(out))
        else:
            self.lib.dc_decode_ex(data, len(data), address, 1 if amd else 0, chip.encode() if chip else None,
                                  ctypes.byref(out))
        status = STATUSES[out.status] if 0 <= out.status < len(STATUSES) else "error"
        extra = _shim_extra(out)
        if status != "ok":
            return Decoded(self.name, self.version, amd, status, extra=extra)
        fields = []
        if out.disp_offset >= 0 and out.disp_size:
            fields.append((out.disp_offset, out.disp_size))
        for index in range(2):
            if out.imm_offset[index] >= 0 and out.imm_size[index]:
                fields.append((out.imm_offset[index], out.imm_size[index]))
        return Decoded(
            self.name, self.version, amd, "ok", out.length, FLOWS[out.flow] if 0 <= out.flow < len(FLOWS) else "other",
            bool(out.indirect), out.target if out.has_target else None, bool(out.counter), out.target_ip_bits,
            out.encoded_disp_bits, out.operand_bits, out.address_bits, out.stack_bits,
            out.ret_imm_value if out.ret_imm else None, out.int_vector if out.int_vector >= 0 else None,
            tuple(sorted(set(fields))), out.mnemonic.decode(errors="replace"),
            self.derivation if out.has_target else "",
            target_kind=TARGET_KINDS[out.target_kind] if 0 <= out.target_kind < len(TARGET_KINDS) else "unknown",
            extra=extra)

    def chip_isa_sets(self, chip: str) -> list | None:
        """The ISA sets the decoder accepts under `chip` (sorted), None if the chip is unknown / unsupported."""
        names, index = [], 1
        while True:
            name = self.lib.dc_isa_set_name(index)
            if name is None:
                if index == 1:
                    return None   # (this decoder has no ISA-set catalogue: chip profiles are XED's)
                break
            valid = self.lib.dc_isa_set_valid_for_chip(index, chip.encode())
            if valid < 0:
                return None
            if valid:
                names.append(name.decode())
            index += 1
        return sorted(names)


# -- iced-x86 --------------------------------------------------------------------------------

class _Iced:
    name = "iced"

    def __init__(self) -> None:
        path = str(DECODERS / "py")
        if path not in sys.path:
            sys.path.insert(0, path)
        import iced_x86

        self.iced = iced_x86
        self.version = f"iced-x86 {getattr(iced_x86, '__version__', '1.22.0')}"
        self.mnemonics = {value: name for name, value in vars(iced_x86.Mnemonic).items() if not name.startswith("_")}
        self.op_kinds = iced_x86.OpKind
        public = lambda enum: {value: name for name, value in vars(enum).items() if not name.startswith("_")}
        self.errors = public(iced_x86.DecoderError)
        self.features = public(iced_x86.CpuidFeature)
        self.registers = {value: name.lower() for value, name in public(iced_x86.Register).items()}
        self.flow_controls = public(iced_x86.FlowControl)
        self.info_factory = iced_x86.InstructionInfoFactory()
        rf = iced_x86.RflagsBits
        # iced RflagsBits -> architectural positions; among the system flags iced reports IF and AC only
        self.rflags_map = [(rf.CF, 0), (rf.PF, 2), (rf.AF, 4), (rf.ZF, 6), (rf.SF, 7), (rf.IF, 9), (rf.DF, 10),
                           (rf.OF, 11), (rf.AC, 18)]

    def decode(self, data: bytes, address: int, amd: bool) -> Decoded:
        x = self.iced
        options = x.DecoderOptions.AMD if amd else x.DecoderOptions.NONE
        decoder = x.Decoder(64, data, options, ip=address)
        instr = decoder.decode()
        error = decoder.last_error
        error_name = self.errors.get(error, str(error))
        if error == x.DecoderError.NO_MORE_BYTES:
            return Decoded(self.name, self.version, amd, "no_more_data", extra={"error": error_name})
        if error != x.DecoderError.NONE or instr.is_invalid:
            return Decoded(self.name, self.version, amd, "invalid", extra={"error": error_name})
        m = x.Mnemonic
        mnemonic = instr.mnemonic
        name = self.mnemonics.get(mnemonic, str(mnemonic))
        flow, counter = "none", False
        if instr.is_call_far or instr.is_call_far_indirect:
            flow = "call_far"
        elif instr.is_call_near or instr.is_call_near_indirect:
            flow = "call_near"
        elif instr.is_jmp_far or instr.is_jmp_far_indirect:
            flow = "jmp_far"
        elif instr.is_jmp_short_or_near or instr.is_jmp_near_indirect:
            flow = "jmp_near"
        elif instr.is_loop or instr.is_loopcc or instr.is_jcx_short:
            flow, counter = "jcc", True
        elif instr.is_jcc_short_or_near:
            flow = "jcc"
        elif mnemonic == m.RET:
            flow = "ret_near"
        elif mnemonic == m.RETF:
            flow = "ret_far"
        elif mnemonic in (m.IRET, m.IRETD, m.IRETQ):
            flow = "iret"
        else:
            flow = {m.INT3: "int3", m.INT: "int_n", m.INT1: "int1", m.INTO: "into", m.UD0: "ud", m.UD1: "ud",
                    m.UD2: "ud", m.SYSCALL: "syscall", m.SYSENTER: "sysenter", m.SYSRET: "sysret",
                    m.SYSEXIT: "sysret", m.HLT: "hlt", m.XBEGIN: "xbegin", m.XABORT: "xabort",
                    m.XEND: "xend",
                    # (iced names the REX.W forms apart; Zydis / XED fold them into sysret / sysexit)
                    m.SYSRETQ: "sysret", m.SYSEXITQ: "sysret"}.get(mnemonic, "none")
            if flow == "none" and instr.flow_control not in (x.FlowControl.NEXT,):
                flow = "other"
        k = self.op_kinds
        target, ip_bits, indirect = None, 0, False
        target_kind = "none"
        if flow in ("call_near", "jmp_near"):
            target_kind = {k.MEMORY: "memory", k.REGISTER: "register", k.NEAR_BRANCH16: "direct",
                           k.NEAR_BRANCH32: "direct", k.NEAR_BRANCH64: "direct"}.get(instr.op0_kind, "unknown")
        if flow in ("call_near", "jmp_near", "jcc", "xbegin"):
            kind = instr.op0_kind
            if kind in (k.NEAR_BRANCH16, k.NEAR_BRANCH32, k.NEAR_BRANCH64):
                target = instr.near_branch_target
                ip_bits = {k.NEAR_BRANCH16: 16, k.NEAR_BRANCH32: 32, k.NEAR_BRANCH64: 64}[kind]
            else:
                indirect = True
                ip_bits = instr.op_code().operand_size or 64
        elif flow in ("call_far", "jmp_far") and instr.op0_kind == k.MEMORY:
            indirect = True
        offsets = decoder.get_constant_offsets(instr)
        fields = []
        if offsets.has_displacement:
            fields.append((offsets.displacement_offset, offsets.displacement_size))
        if offsets.has_immediate:
            fields.append((offsets.immediate_offset, offsets.immediate_size))
        if offsets.has_immediate2:
            fields.append((offsets.immediate_offset2, offsets.immediate_size2))
        disp_bits = 0
        if target is not None:
            disp_bits = 8 * (offsets.immediate_size if offsets.has_immediate else offsets.displacement_size)
        code = instr.op_code()
        operand_bits = code.operand_size or (ip_bits or 0)
        address_bits = code.address_size
        if not address_bits:
            # (memory operand: its base / index register width decides the address size, 67 prefix)
            registers = [reg for reg in (instr.memory_base, instr.memory_index) if reg != x.Register.NONE]
            sizes = {x.RegisterExt.size(reg) * 8 for reg in registers
                     if reg not in (x.Register.RIP, x.Register.EIP)}
            if instr.memory_base == x.Register.EIP:
                sizes.add(32)
            address_bits = sizes.pop() if len(sizes) == 1 else 64
        ret_imm = instr.immediate16 if flow in ("ret_near", "ret_far") and instr.op_count == 1 else None
        vector = instr.immediate8 if flow == "int_n" else None
        stack = 64   # (long mode: the stack width; push / pop sizes follow the operand size)
        return Decoded(self.name, self.version, amd, "ok", instr.len, flow, indirect, target, counter, ip_bits,
                       disp_bits, operand_bits, address_bits, stack, ret_imm, vector, tuple(sorted(set(fields))),
                       name, "decoder" if target is not None else "", target_kind=target_kind,
                       extra=self._extra(instr, code, mnemonic))

    def _extra(self, instr, code, mnemonic) -> dict:
        """The raw iced ISA-fact evidence (ISA facts r3 s1 layer 1; s2: the three privilege flags)."""
        m, k = self.iced.Mnemonic, self.op_kinds
        segments = set()
        if mnemonic not in (m.LEA, m.NOP):   # (address-only / hint operands touch no segment)
            for index in range(instr.op_count):
                kind = instr.op_kind(index)
                if kind in (k.MEMORY, k.MEMORY_SEG_SI, k.MEMORY_SEG_ESI, k.MEMORY_SEG_RSI,
                            k.MEMORY_SEG_DI, k.MEMORY_SEG_EDI, k.MEMORY_SEG_RDI):
                    segments.add(self.registers.get(instr.memory_segment, "?"))
                elif kind in (k.MEMORY_ESDI, k.MEMORY_ESEDI, k.MEMORY_ESRDI):
                    segments.add("es")
        order = [name for name, _ in SEGMENTS]
        return {
            "error": "", "chip": "",
            "flow_detail": {m.SYSRET: "sysret", m.SYSRETQ: "sysret", m.SYSEXIT: "sysexit",
                            m.SYSEXITQ: "sysexit"}.get(mnemonic, "none"),
            "must_be_cpl0": bool(code.must_be_cpl0), "is_privileged": bool(code.is_privileged),
            "may_require_cpl0": bool(code.may_require_cpl0),
            "cpuid_features": sorted(self.features.get(f, str(f)) for f in instr.cpuid_features()),
            "mem_segments": sorted(segments, key=lambda s: order.index(s) if s in order else len(order)),
            **self._form_evidence(instr, code, mnemonic)}

    def _rflags(self, bits: int) -> int:
        return sum(1 << position for flag, position in self.rflags_map if bits & flag)

    def _form_evidence(self, instr, code, mnemonic) -> dict:
        """Layout-revision-4 evidence from iced (2b): flow control as category, RFLAGS (IF / AC only among the
        system flags), segment-register operands, explicit operand kinds, effective LOCK / REP, memory accesses
        (InstructionInfoFactory used memory: implicit stack / string accesses included)."""
        x, k, m = self.iced, self.op_kinds, self.iced.Mnemonic
        R = x.RegisterExt
        string_kinds = {k.MEMORY_SEG_SI, k.MEMORY_SEG_ESI, k.MEMORY_SEG_RSI, k.MEMORY_SEG_DI, k.MEMORY_SEG_EDI,
                        k.MEMORY_SEG_RDI, k.MEMORY_ESDI, k.MEMORY_ESEDI, k.MEMORY_ESRDI}
        immediates = {k.IMMEDIATE8, k.IMMEDIATE8_2ND, k.IMMEDIATE16, k.IMMEDIATE32, k.IMMEDIATE64,
                      k.IMMEDIATE8TO16, k.IMMEDIATE8TO32, k.IMMEDIATE8TO64, k.IMMEDIATE32TO64}
        branches = {k.NEAR_BRANCH16, k.NEAR_BRANCH32, k.NEAR_BRANCH64, k.FAR_BRANCH16, k.FAR_BRANCH32}
        sig, sreg, explicit_memory = [], False, None
        for index in range(instr.op_count):
            kind = instr.op_kind(index)
            if kind == k.REGISTER:
                reg = instr.op_register(index)
                if R.is_segment_register(reg):
                    sreg = True
                    sig.append("s")
                elif R.is_gpr(reg):
                    sig.append("g")
                elif R.is_mm(reg):
                    sig.append("m")
                elif R.is_xmm(reg):
                    sig.append("x")
                elif R.is_ymm(reg) or R.is_zmm(reg) or R.is_tmm(reg):
                    sig.append("y")
                elif R.is_k(reg):
                    sig.append("k")
                elif R.is_cr(reg) or R.is_dr(reg):
                    sig.append("c")
                elif R.is_st(reg):
                    sig.append("f")
                else:
                    sig.append("?")
            elif kind == k.MEMORY:
                sig.append("A" if mnemonic == m.LEA else "M")
                explicit_memory = index
            elif kind in string_kinds:
                continue   # (implicit string memory: not an explicit operand in XED / Zydis terms)
            elif kind in immediates:
                sig.append("i")
            elif kind in branches:
                sig.append("r")
            else:
                sig.append("?")
        rep = ""
        if code.can_use_rep_prefix and (instr.has_rep_prefix or instr.has_repe_prefix):
            rep = "rep"
        elif code.can_use_repne_prefix and instr.has_repne_prefix:
            rep = "repne"
        memory, overflow = [], False
        if mnemonic not in (m.LEA, m.NOP):
            for used in self.info_factory.info(instr).used_memory():
                if used.access in (x.OpAccess.NO_MEM_ACCESS, x.OpAccess.NONE):
                    continue
                if len(memory) >= MAX_MEM:
                    overflow = True
                    break
                base = self.registers.get(used.base, "")
                is_explicit = (explicit_memory is not None and used.base == instr.memory_base
                               and used.index == instr.memory_index and not any(
                                   item["role"] == "explicit" for item in memory))
                role = "explicit" if is_explicit else (
                    "stack" if base in ("rsp", "esp", "sp") else "string_source" if base in ("rsi", "esi", "si")
                    else "string_dest" if base in ("rdi", "edi", "di") else "other")
                access = used.access
                read = access in (x.OpAccess.READ, x.OpAccess.COND_READ, x.OpAccess.READ_WRITE,
                                  x.OpAccess.READ_COND_WRITE)
                write = access in (x.OpAccess.WRITE, x.OpAccess.COND_WRITE, x.OpAccess.READ_WRITE,
                                   x.OpAccess.READ_COND_WRITE)
                string_rep = bool(rep) and role in ("string_source", "string_dest")
                cond_read = access == x.OpAccess.COND_READ or (string_rep and read)
                cond_write = access in (x.OpAccess.COND_WRITE, x.OpAccess.READ_COND_WRITE) or (string_rep and write)
                memory.append({"segment": self.registers.get(used.segment, ""), "read": read, "write": write,
                               "role": role, "cond_read": cond_read, "cond_write": cond_write,
                               "conditional": cond_read or cond_write,
                               "operand_index": explicit_memory if is_explicit else None})
        written = (instr.rflags_written | instr.rflags_cleared | instr.rflags_set | instr.rflags_undefined
                   | instr.rflags_modified)
        return {"category": self.flow_controls.get(instr.flow_control, str(instr.flow_control)),
                "is_input_output": bool(code.is_input_output),
                "rflags_read": self._rflags(instr.rflags_read), "rflags_written": self._rflags(written),
                "sreg_operand": sreg, "lock": bool(instr.has_lock_prefix), "rep": rep, "op_sig": "".join(sig),
                "mem_overflow": overflow, "memory": memory, "iform": "",
                # an explicit memory operand that no used-memory entry matched: the access list is incomplete
                "memory_complete": not overflow and (explicit_memory is None
                                                     or any(m["role"] == "explicit" for m in memory))}


_VOTERS = {}


def voter(name: str):
    """iced / zydis / xed (loaded once)."""
    if name not in _VOTERS:
        if name == "iced":
            _VOTERS[name] = _Iced()
        elif name == "zydis":
            _VOTERS[name] = _Shim("zydis", DECODERS / "lib" / "libdc_zydis.so", "decoder")
        elif name == "xed":
            _VOTERS[name] = _Shim("xed", DECODERS / "lib" / "libdc_xed.so",
                                  "computed: next IP + displacement at the operand width")
        else:
            raise ValueError(f"unknown voter {name!r}")
    return _VOTERS[name]


# XED chip profiles (ISA facts r3 s3 F4): profiles of ONE decoder, never voters, never counted in votes.
# xed:g1 is the G1 voter setting itself (input chip unset); the other two name their chip enum.
# Baseline: P4PRESCOTT_NOLAHF is the smallest chip of the pinned XED build with LONGMODE (33 ISA sets; no
# LAHF / SAHF in 64-bit mode, like the first x86-64 parts; it does include SSE3, CMPXCHG16B, MONITOR, PAUSE,
# so splits on those come from the SDM split table, not from the profile comparison). Measured 2026-11-26.
XED_PROFILES = {"xed:g1": None, "xed:baseline": "P4PRESCOTT_NOLAHF", "xed:all": "ALL"}


def decode_without(isa_set: str, data: bytes, address: int) -> Decoded:
    """XED under XED_CHIP_ALL with one ISA set removed (r3 s3 F4: the deciding feature of a split candidate)."""
    return voter("xed").decode(bytes(data[:MAX_LENGTH]), address, False, without=isa_set)


def decode_profile(profile: str, data: bytes, address: int) -> Decoded:
    """One XED chip-profile decode of the same (verified) bytes."""
    return voter("xed").decode(bytes(data[:MAX_LENGTH]), address, False, XED_PROFILES[profile])


def profile_catalogue() -> dict:
    """{profile: {"chip": name, "isa_sets": [...] | None}} for the header digest (ISA facts r3 s5)."""
    xed = voter("xed")
    return {profile: {"chip": chip, "isa_sets": xed.chip_isa_sets(chip) if chip else None}
            for profile, chip in XED_PROFILES.items()}


# the votes of design r1 s5: Intel mode iced, Zydis, XED; AMD mode iced, Zydis
INTEL_VOTERS = ("iced", "zydis", "xed")
AMD_VOTERS = ("iced", "zydis")


def decode(name: str, data: bytes, address: int, amd: bool) -> Decoded:
    return voter(name).decode(bytes(data[:MAX_LENGTH]), address, amd)


def ballot(data: bytes, address: int) -> dict:
    """{"intel": (Decoded, ...), "amd": (Decoded, ...)} for one window."""
    return {"intel": tuple(decode(name, data, address, False) for name in INTEL_VOTERS),
            "amd": tuple(decode(name, data, address, True) for name in AMD_VOTERS)}


def manifest() -> dict:
    import json

    path = DECODERS / "manifest.json"
    return json.loads(path.read_text()) if path.exists() else {}
