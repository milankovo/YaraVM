import struct

from ida_bytes import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_segment import *
from ida_name import *
from ida_netnode import *
from ida_xref import *
from ida_idaapi import *
import ida_idp
import idaapi
import ida_xref
import ida_frame
import ida_offset
import ida_pro
import idc

import enum


class FL(enum.IntFlag):
    OP1 = enum.auto()
    OP1_8 = enum.auto()
    OP1_16 = enum.auto()
    OP1_32 = enum.auto()
    OP1_REL_16 = enum.auto()
    OP1_REL_32 = enum.auto()
    OP1_REL_64 = enum.auto()
    OP1_ABS_64 = enum.auto()
    OP1_RULE_IDX_32 = enum.auto()
    OP1_RULE_IDX_64 = enum.auto()

    OP2_8 = enum.auto()
    OP2_16 = enum.auto()
    OP2_32 = enum.auto()
    OP2_64 = enum.auto()
    OP2_REL_16 = enum.auto()
    OP2_REL_32 = enum.auto()
    OP2_REL_64 = enum.auto()
    OP2_RULE_IDX_32 = enum.auto()
    OP2_RULE_IDX_64 = enum.auto()

    OP3_8 = enum.auto()
    OP3_16 = enum.auto()
    OP3_32 = enum.auto()
    OP3_64 = enum.auto()
    OP3_REL_16 = enum.auto()
    OP3_REL_32 = enum.auto()
    OP3_REL_64 = enum.auto()
    OP3_RULE_IDX_32 = enum.auto()
    OP3_RULE_IDX_64 = enum.auto()

    RE_CLASS = enum.auto()  # class
    NOFLOW = enum.auto()  # halt


OPCODES = [
    [255, "OP_HALT", FL.NOFLOW],
    [254, "OP_NOP", 0],
    [1, "OP_AND", 0],
    [2, "OP_OR", 0],
    [3, "OP_NOT", 0],
    [4, "OP_BITWISE_NOT", 0],
    [5, "OP_BITWISE_AND", 0],
    [6, "OP_BITWISE_OR", 0],
    [7, "OP_BITWISE_XOR", 0],
    [8, "OP_SHL", 0],
    [9, "OP_SHR", 0],
    [10, "OP_MOD", 0],
    [11, "OP_INT_TO_DBL", FL.OP1],
    [12, "OP_STR_TO_BOOL", 0],
    [13, "OP_PUSH", FL.OP1_ABS_64],
    [14, "OP_POP", 0],
    [15, "OP_CALL", FL.OP1],
    [16, "OP_OBJ_LOAD", FL.OP1],
    [17, "OP_OBJ_VALUE", 0],
    [18, "OP_OBJ_FIELD", FL.OP1],
    [19, "OP_INDEX_ARRAY", 0],
    [20, "OP_COUNT", 0],
    [21, "OP_LENGTH", 0],
    [22, "OP_FOUND", 0],
    [23, "OP_FOUND_AT", 0],
    [24, "OP_FOUND_IN", 0],
    [25, "OP_OFFSET", 0],
    [26, "OP_OF", FL.OP1],  # TODO: use MACRO_OF_STRING here
    [27, "OP_PUSH_RULE", FL.OP1_RULE_IDX_64],
    # jump 32bit, rule index 32bit
    # // After the opcode there's an int32_t corresponding to the jump's
    #  // offset and an uint32_t corresponding to the rule's index.
    [28, "OP_INIT_RULE", FL.OP1_REL_32 | FL.OP2_RULE_IDX_32],
    [29, "OP_MATCH_RULE", FL.OP1_RULE_IDX_64],
    [30, "OP_INCR_M", FL.OP1],
    [31, "OP_CLEAR_M", FL.OP1],
    [32, "OP_ADD_M", FL.OP1],
    [33, "OP_POP_M", FL.OP1],
    [34, "OP_PUSH_M", FL.OP1],
    [35, "OP_SET_M", FL.OP1],
    [36, "OP_SWAPUNDEF", FL.OP1],
    [37, "OP_FILESIZE", 0],
    [38, "OP_ENTRYPOINT", 0],
    [39, "OP_CONTAINS", 0],
    [40, "OP_MATCHES", 0],
    [41, "OP_IMPORT", FL.OP1],
    [42, "OP_LOOKUP_DICT", 0],
    # Not used
    [43, "OP_JUNDEF", FL.OP1_REL_32],
    [44, "OP_JUNDEF_P", FL.OP1_REL_32],
    [45, "OP_JNUNDEF", FL.OP1_REL_32],
    # Not used
    [46, "OP_JNUNDEF_P", FL.OP1_REL_32],
    [47, "OP_JFALSE", FL.OP1_REL_32],
    [48, "OP_JFALSE_P", FL.OP1_REL_32],
    [49, "OP_JTRUE", FL.OP1_REL_32],
    [50, "OP_JTRUE_P", FL.OP1_REL_32],
    [51, "OP_JL_P", FL.OP1_REL_32],
    [52, "OP_JLE_P", FL.OP1_REL_32],
    [53, "OP_ITER_NEXT", 0],
    [54, "OP_ITER_START_ARRAY", 0],
    [55, "OP_ITER_START_DICT", 0],
    [56, "OP_ITER_START_INT_RANGE", 0],
    [57, "OP_ITER_START_INT_ENUM", 0],
    [58, "OP_ITER_START_STRING_SET", FL.OP1_REL_32],
    [59, "OP_ITER_CONDITION", 0],
    [60, "OP_ITER_END", 0],
    [61, "OP_JZ", FL.OP1_REL_32],
    [62, "OP_JZ_P", FL.OP1_REL_32],
    [63, "OP_PUSH_8", FL.OP1_8],
    [64, "OP_PUSH_16", FL.OP1_16],
    [65, "OP_PUSH_32", FL.OP1_32],
    [66, "OP_PUSH_U", 0],
    [67, "OP_CONTAINS", 0],
    [68, "OP_STARTSWITH", 0],
    [69, "OP_ENDSWITH", 0],
    [70, "OP_ICONTAINS", 0],
    [71, "OP_ISTARTSWITH", 0],
    [72, "OP_IENDSWITH", 0],
    [73, "OP_IEQUALS", 0],
    [74, "OP_OF_PERCENT", FL.OP1],  # TODO: use MACRO_OF_STRING here
    [75, "OP_OF_FOUND_IN", 0],
    [76, "OP_COUNT_IN", 0],
    [77, "OP_DEFINED", 0],
    [78, "OP_ITER_START_TEXT_STRING_SET", 0],
    [79, "OP_OF_FOUND_AT", 0],
    [(100 + 0), "OP_INT_EQ", 0],
    [(100 + 1), "OP_INT_NEQ", 0],
    [(100 + 2), "OP_INT_LT", 0],
    [(100 + 3), "OP_INT_GT", 0],
    [(100 + 4), "OP_INT_LE", 0],
    [(100 + 5), "OP_INT_GE", 0],
    [(100 + 6), "OP_INT_ADD", 0],
    [(100 + 7), "OP_INT_SUB", 0],
    [(100 + 8), "OP_INT_MUL", 0],
    [(100 + 9), "OP_INT_DIV", 0],
    [(100 + 10), "OP_INT_MINUS", 0],
    [(120 + 0), "OP_DBL_EQ", 0],
    [(120 + 1), "OP_DBL_NEQ", 0],
    [(120 + 2), "OP_DBL_LT", 0],
    [(120 + 3), "OP_DBL_GT", 0],
    [(120 + 4), "OP_DBL_LE", 0],
    [(120 + 5), "OP_DBL_GE", 0],
    [(120 + 6), "OP_DBL_ADD", 0],
    [(120 + 7), "OP_DBL_SUB", 0],
    [(120 + 8), "OP_DBL_MUL", 0],
    [(120 + 9), "OP_DBL_DIV", 0],
    [(120 + 10), "OP_DBL_MINUS", 0],
    [(140 + 0), "OP_STR_EQ", 0],
    [(140 + 1), "OP_STR_NEQ", 0],
    [(140 + 2), "OP_STR_LT", 0],
    [(140 + 3), "OP_STR_GT", 0],
    [(140 + 4), "OP_STR_LE", 0],
    [(140 + 5), "OP_STR_GE", 0],
    [240, "OP_READ_INT", 0],
    [(240 + 0), "OP_INT8", 0],
    [(240 + 1), "OP_INT16", 0],
    [(240 + 2), "OP_INT32", 0],
    [(240 + 3), "OP_UINT8", 0],
    [(240 + 4), "OP_UINT16", 0],
    [(240 + 5), "OP_UINT32", 0],
    [(240 + 6), "OP_INT8BE", 0],
    [(240 + 7), "OP_INT16BE", 0],
    [(240 + 8), "OP_INT32BE", 0],
    [(240 + 9), "OP_UINT8BE", 0],
    [(240 + 10), "OP_UINT16BE", 0],
    [(240 + 11), "OP_UINT32BE", 0],
    [0xA0, "RE_OPCODE_ANY", 0],
    [0xA2, "RE_OPCODE_LITERAL", FL.OP1_8],
    [0xA4, "RE_OPCODE_MASKED_LITERAL", FL.OP1_8 | FL.OP2_8],
    [0xA5, "RE_OPCODE_CLASS", FL.RE_CLASS],
    [0xA7, "RE_OPCODE_WORD_CHAR", 0],
    [0xA8, "RE_OPCODE_NON_WORD_CHAR", 0],
    [0xA9, "RE_OPCODE_SPACE", 0],
    [0xAA, "RE_OPCODE_NON_SPACE", 0],
    [0xAB, "RE_OPCODE_DIGIT", 0],
    [0xAC, "RE_OPCODE_NON_DIGIT", 0],
    [0xAD, "RE_OPCODE_MATCH", FL.NOFLOW],
    [0xAE, "RE_OPCODE_NOT_LITERAL", FL.OP1_8],
    [0xAF, "RE_OPCODE_MASKED_NOT_LITERAL", FL.OP1_8 | FL.OP2_8],
    [0xB0, "RE_OPCODE_MATCH_AT_END", 0],
    [0xB1, "RE_OPCODE_MATCH_AT_START", 0],
    [0xB2, "RE_OPCODE_WORD_BOUNDARY", 0],
    [0xB3, "RE_OPCODE_NON_WORD_BOUNDARY", 0],
    [0xB4, "RE_OPCODE_REPEAT_ANY_GREEDY", FL.OP1_16 | FL.OP2_16],
    [0xB5, "RE_OPCODE_REPEAT_ANY_UNGREEDY", FL.OP1_16 | FL.OP2_16],
    [0xC0, "RE_OPCODE_SPLIT_A", FL.OP1_8 | FL.OP2_REL_16],
    [0xC1, "RE_OPCODE_SPLIT_B", FL.OP1_8 | FL.OP2_REL_16],
    [0xC2, "RE_OPCODE_JUMP", FL.OP1_REL_16],
    [0xC3, "RE_OPCODE_REPEAT_START_GREEDY", FL.OP1_16 | FL.OP2_16 | FL.OP3_REL_32],
    [0xC4, "RE_OPCODE_REPEAT_END_GREEDY", FL.OP1_16 | FL.OP2_16 | FL.OP3_REL_32],
    [0xC5, "RE_OPCODE_REPEAT_START_UNGREEDY", FL.OP1_16 | FL.OP2_16 | FL.OP3_REL_32],
    [0xC6, "RE_OPCODE_REPEAT_END_UNGREEDY", FL.OP1_16 | FL.OP2_16 | FL.OP3_REL_32],
]


ITYPES = set()
ITYPETODEF = {}
ITYPETOFLAGS = {}
OPCODETOITYPE = {}
CODES = set()
OPTODEF = {}

for i, oc in enumerate(OPCODES):
    itype = i
    ITYPES.add(itype)
    ITYPETODEF[itype] = oc
    ITYPETOFLAGS[itype] = oc[2]

    OPTODEF[oc[0]] = oc
    OPCODETOITYPE[oc[0]] = itype
    CODES.add(oc[0])

MNEM_WIDTH = 16


def to_signed(n, bits):
    if n & (1 << (bits - 1)):
        return n - (1 << bits)
    return n


def class_to_str(class_):
    """
    Convert a class to a string
    class_ is a list of bytes
    every byte is a bitfield
    returns a string
    """

    s = []
    for j, b in enumerate(class_):
        for i in range(8):
            if b & (1 << i):
                s.append(chr(i + j * 8))

    return "".join(s)


# extract bitfield occupying bits high..low from val (inclusive, start from 0)
def BITS(val, low, high):
    return (val >> low) & ((1 << (high - low + 1)) - 1)


# extract one bit
def BIT(val, bit):
    return (val >> bit) & 1


# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m


# check if operand is register reg
def is_reg(op, reg):
    return op.type == o_reg and op.reg == reg


# check if operand is immediate value val
def is_imm(op, val):
    return op.type == o_imm and op.value == val


# are operands equal?
def same_op(op1, op2):
    return (
        op1.type == op2.type
        and op1.reg == op2.reg
        and op1.value == op2.value
        and op1.addr == op2.addr
        and op1.flags == op2.flags
        and op1.specval == op2.specval
        and op1.dtype == op2.dtype
    )


# is sp delta fixed by the user?
def is_fixed_spd(ea):
    return (get_aflags(ea) & AFL_FIXEDSPD) != 0


# ----------------------------------------------------------------------
class yara_processor_t(processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 501

    # Processor features
    flag = PR_SEGS | PR_DEFSEG32 | PR_USE32 | PR_USE64 | PRN_HEX | PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ["yaravm"]

    # long processor names
    # No restriction on name lengthes.
    plnames = ["Yara Byte code"]

    # size of a segment register in bytes
    segreg_size = 0

    # Array of typical code start sequences (optional)
    # codestart = ['\x60\x00']  # 60 00 xx xx: MOVqw         SP, SP-delta

    # Array of 'return' instruction opcodes (optional)
    # retcodes = ['\x04\x00']   # 04 00: RET

    # You should define 2 virtual segment registers for CS and DS.
    # Let's call them rVcs and rVds.

    # icode of the first instruction
    instruc_start = 0

    #
    #      Size of long double (tbyte) for this processor
    #      (meaningful only if ash.a_tbyte != NULL)
    #
    tbyte_size = 0

    # only one assembler is supported
    assembler = {
        # flag
        "flag": ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,
        # user defined flags (local only for IDP)
        # you may define and use your own bits
        "uflag": 0,
        # Assembler name (displayed in menus)
        "name": "Yara bytecode assembler",
        # org directive
        "origin": "org",
        # end directive
        "end": "end",
        # comment string (see also cmnt2)
        "cmnt": ";",
        # ASCII string delimiter
        "ascsep": '"',
        # ASCII char constant delimiter
        "accsep": "'",
        # ASCII special chars (they can't appear in character and ascii constants)
        "esccodes": "\"'",
        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        "a_ascii": "db",
        # byte directive
        "a_byte": "db",
        # word directive
        "a_word": "dw",
        # remove if not allowed
        "a_dword": "dd",
        # remove if not allowed
        "a_qword": "dq",
        # remove if not allowed
        "a_oword": "xmmword",
        # float;  4bytes; remove if not allowed
        "a_float": "dd",
        # double; 8bytes; NULL if not allowed
        "a_double": "dq",
        # long double;    NULL if not allowed
        "a_tbyte": "dt",
        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        "a_dups": "#d dup(#v)",
        # uninitialized data directive (should include '%s' for the size of data)
        "a_bss": "%s dup ?",
        # 'seg ' prefix (example: push seg seg001)
        "a_seg": "seg",
        # current IP (instruction pointer) symbol in assembler
        "a_curip": "$",
        # "public" name keyword. NULL-gen default, ""-do not generate
        "a_public": "public",
        # "weak"   name keyword. NULL-gen default, ""-do not generate
        "a_weak": "weak",
        # "extrn"  name keyword
        "a_extrn": "extrn",
        # "comm" (communal variable)
        "a_comdef": "",
        # "align" keyword
        "a_align": "align",
        # Left and right braces used in complex expressions
        "lbrace": "(",
        "rbrace": ")",
        # %  mod     assembler time operation
        "a_mod": "%",
        # &  bit and assembler time operation
        "a_band": "&",
        # |  bit or  assembler time operation
        "a_bor": "|",
        # ^  bit xor assembler time operation
        "a_xor": "^",
        # ~  bit not assembler time operation
        "a_bnot": "~",
        # << shift left assembler time operation
        "a_shl": "<<",
        # >> shift right assembler time operation
        "a_shr": ">>",
        # size of type (format string)
        "a_sizeof_fmt": "size %s",
    }  # Assembler

    # ----------------------------------------------------------------------
    def get_data_width_fl(self, sz):
        """Returns a flag given the data width number"""
        if sz == 0:
            return self.FL_B
        elif sz == self.IMMDATA_16:
            return self.FL_W
        elif sz == self.IMMDATA_32:
            return self.FL_D
        elif sz == self.IMMDATA_64:
            return self.FL_Q

    # ----------------------------------------------------------------------
    def next_data_value(self, insn, sz):
        """Returns a value depending on the data widh number"""
        if sz == 0:
            return insn.get_next_byte()
        elif sz == self.IMMDATA_16:
            return insn.get_next_word()
        elif sz == self.IMMDATA_32:
            return insn.get_next_dword()
        elif sz == self.IMMDATA_64:
            return insn.get_next_qword()
        else:
            raise Exception("Invalid width!")

    # ----------------------------------------------------------------------
    def get_data_dt(self, sz):
        """Returns a dt_xxx on the data widh number"""
        if sz == 0:
            return dt_byte
        elif sz == self.IMMDATA_16:
            return dt_word
        elif sz == self.IMMDATA_32:
            return dt_dword
        elif sz == self.IMMDATA_64:
            return dt_qword
        else:
            raise Exception("Invalid width!")

    # ----------------------------------------------------------------------
    def native_dt(self):
        return dt_qword if self.PTRSZ == 8 else dt_dword

    # ----------------------------------------------------------------------
    def get_sz_to_bits(self, sz):
        """Returns size in bits of the data widh number"""
        if sz == self.IMMDATA_16:
            return 16
        elif sz == self.IMMDATA_32:
            return 32
        elif sz == self.IMMDATA_64:
            return 64
        else:
            return 8

    # ----------------------------------------------------------------------
    def dt_to_bits(self, dt):
        """Returns the size in bits given a dt_xxx"""
        if dt == dt_byte:
            return 8
        elif dt == dt_word:
            return 16
        elif dt == dt_dword:
            return 32
        elif dt == dt_qword:
            return 64

    # ----------------------------------------------------------------------
    def dt_to_width(self, dt):
        """Returns OOFW_xxx flag given a dt_xxx"""
        if dt == dt_byte:
            return OOFW_8
        elif dt == dt_word:
            return OOFW_16
        elif dt == dt_dword:
            return OOFW_32
        elif dt == dt_qword:
            return OOFW_64

    # ----------------------------------------------------------------------
    def fl_to_str(self, fl):
        """Given a flag, it returns a string. (used during output)"""
        if fl & self.FL_B != 0:
            return "b"
        elif fl & self.FL_W != 0:
            return "w"
        elif fl & self.FL_D != 0:
            return "d"
        elif fl & self.FL_Q != 0:
            return "q"

    # ----------------------------------------------------------------------
    # Processor module callbacks
    #
    # ----------------------------------------------------------------------
    def ev_get_frame_retsize(self, frsize, pfn):
        ida_pro.int_pointer.frompointer(frsize).assign(16)
        return 1

    # ----------------------------------------------------------------------
    def ev_get_autocmt(self, insn: idaapi.insn_t):
        if insn.itype not in self.instruc:
            return None
        if "cmt" in self.instruc[insn.itype]:
            return self.instruc[insn.itype]["cmt"](insn)

    # ----------------------------------------------------------------------
    def ev_can_have_type(self, op):
        return 1 if op.type in [o_imm, o_displ, o_mem] else 0

    # ----------------------------------------------------------------------
    def ev_is_align_insn(self, ea):
        return 2 if get_word(ea) == 0 else 0

    # ----------------------------------------------------------------------
    def ev_newfile(self, filename):
        return 0

    # ----------------------------------------------------------------------
    def ev_oldfile(self, filename):
        return 0

    # ----------------------------------------------------------------------
    def ev_out_header(self, ctx):
        # ctx.out_line("; natural unit size: %d bits" % (self.PTRSZ*8))
        ctx.flush_outbuf(0)
        return 1

    # ----------------------------------------------------------------------
    def ev_may_be_func(self, insn: idaapi.insn_t, state):
        # if is_reg(insn.Op1, self.ireg_SP) and insn.Op2.type == o_displ and\
        #    insn.Op2.phrase == self.ireg_SP and (insn.Op2.specval & self.FLo_INDIRECT) == 0:
        #    # mov SP, SP+delta
        #    if SIGNEXT(insn.Op2.addr, self.PTRSZ*8) < 0:
        #        return 100
        #    else:
        #        return 0
        return 10

    # ----------------------------------------------------------------------
    def check_thunk(self, addr):
        """
        Check for EBC thunk at addr
        dd fnaddr - (addr+4), 0, 0, 0
        """
        delta = get_dword(addr)
        fnaddr = (delta + addr + 4) & 0xFFFFFFFF
        if is_off(get_flags(addr), 0):
            # already an offset
            if ida_offset.get_offbase(addr, 0) == addr + 4:
                return fnaddr
            else:
                return None
        # should be followed by three zeroes
        if (
            delta == 0
            or get_dword(addr + 4) != 0
            or get_dword(addr + 8) != 0
            or get_dword(addr + 12) != 0
        ):
            return None
        if segtype(fnaddr) == SEG_CODE:
            # looks good, create the offset
            idc.create_dword(addr)
            if ida_offset.op_offset(
                addr, 0, REF_OFF32 | REFINFO_NOBASE, BADADDR, addr + 4
            ):
                return fnaddr
            else:
                return None

    # ----------------------------------------------------------------------
    def add_stkpnt(self, insn, pfn, v):
        if pfn:
            end = insn.ea + insn.size
            if not is_fixed_spd(end):
                ida_frame.add_auto_stkpnt(pfn, end, v)

    # ----------------------------------------------------------------------
    def trace_sp(self, insn: insn_t):
        """
        Trace the value of the SP and create an SP change point if the current
        instruction modifies the SP.
        """
        return

    # ----------------------------------------------------------------------
    def ev_emu_insn(self, insn: insn_t):
        if insn.itype in ITYPES:
            flags = ITYPETOFLAGS[insn.itype]

            if (flags & FL.NOFLOW) == 0:
                ida_ua.insn_add_cref(insn, insn.ea + insn.size, 0, ida_xref.fl_F)

            if (flags & (FL.OP1_REL_32 | FL.OP1_REL_16 | FL.OP1_REL_64)) != 0:
                ida_ua.insn_add_cref(insn, insn.Op1.addr, 0, ida_xref.fl_JN)

            if (flags & (FL.OP1_ABS_64)) != 0:
                ida_ua.insn_add_dref(insn, insn.Op1.addr, 0, ida_xref.dr_O)

            if (flags & (FL.OP1_RULE_IDX_32)) != 0:
                ida_ua.insn_add_dref(insn, insn.Op1.addr, 0, ida_xref.dr_O)
            if (flags & (FL.OP1_RULE_IDX_64)) != 0:
                ida_ua.insn_add_dref(insn, insn.Op1.addr, 0, ida_xref.dr_O)

            if (flags & (FL.OP2_REL_32 | FL.OP2_REL_16 | FL.OP2_REL_64)) != 0:
                ida_ua.insn_add_cref(insn, insn.Op2.addr, 0, ida_xref.fl_JN)

            if (flags & (FL.OP2_RULE_IDX_32)) != 0:
                ida_ua.insn_add_dref(insn, insn.Op2.addr, 0, ida_xref.dr_O)
            if (flags & (FL.OP2_RULE_IDX_64)) != 0:
                ida_ua.insn_add_dref(insn, insn.Op2.addr, 0, ida_xref.dr_O)

            if (flags & (FL.OP3_REL_32 | FL.OP3_REL_16 | FL.OP3_REL_64)) != 0:
                ida_ua.insn_add_cref(insn, insn.Op3.addr, 0, ida_xref.fl_JN)

            if (flags & (FL.OP3_RULE_IDX_32)) != 0:
                ida_ua.insn_add_dref(insn, insn.Op3.addr, 0, ida_xref.dr_O)
            if (flags & (FL.OP3_RULE_IDX_64)) != 0:
                ida_ua.insn_add_dref(insn, insn.Op3.addr, 0, ida_xref.dr_O)

            return 1
        return 0

    # ----------------------------------------------------------------------
    def ev_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        optype = op.type
        fl = op.specval
        signed = 0  # OOF_SIGNED if fl & self.FLo_SIGNED != 0 else 0
        def_arg = is_defarg(get_flags(ctx.insn.ea), op.n)

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif optype == o_imm:
            # for immediate loads, use the transfer width (type of first operand)
            if op.n == 1:
                width = self.dt_to_width(ctx.insn.Op1.dtype)
            else:
                width = OOFW_32 if self.PTRSZ == 4 else OOFW_64
            ctx.out_value(op, OOFW_IMM | signed | width)

        elif optype in [o_near, o_mem]:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)

        elif optype == o_displ:
            indirect = 0  # fl & self.FLo_INDIRECT != 0
            if indirect:
                ctx.out_symbol("[")

            ctx.out_register(self.reg_names[op.reg])

            if op.addr != 0 or def_arg:
                ctx.out_value(
                    op,
                    OOF_ADDR
                    | (OOFW_32 if self.PTRSZ == 4 else OOFW_64)
                    | signed
                    | OOFS_NEEDSIGN,
                )

            if indirect:
                ctx.out_symbol("]")
        else:
            return False

        return True

    # ----------------------------------------------------------------------
    # Generate the instruction mnemonics

    # ----------------------------------------------------------------------
    # Generate text representation of an instruction in 'ctx.insn' structure.
    # This function shouldn't change the database, flags or anything else.
    # All these actions should be performed only by u_emu() function.
    def ev_out_insn(self, ctx):
        ctx.out_mnemonic()

        ctx.out_one_operand(0)

        for i in range(1, 3):
            op = ctx.insn[i]

            if op.type == o_void:
                break

            ctx.out_symbol(",")
            ctx.out_char(" ")
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    def rule_idx_to_addr(self, idx):
        if self.rules_ea == BADADDR or self.rule_sz == 0:
            self.update_rule_size()
            assert self.rules_ea != BADADDR

        return self.rules_ea + idx * self.rule_sz

    # ----------------------------------------------------------------------
    def ev_ana_insn(self, insn: idaapi.insn_t):
        b = insn.get_next_byte()

        if b not in CODES:
            return 0
        oc = OPTODEF[b]
        insn.itype = OPCODETOITYPE[b]
        flags = oc[2]
        insn.size = 1
        if flags & FL.OP1:
            op_num(insn.Op1, insn.get_next_qword())

        if flags & FL.OP1_8:
            op_num(insn.Op1, insn.get_next_byte())

        if flags & FL.OP1_16:
            op_num(insn.Op1, insn.get_next_word())

        if flags & FL.OP1_32:
            op_num(insn.Op1, insn.get_next_dword())

        if flags & FL.OP1_RULE_IDX_32:
            op_rule(insn.Op1, self.rule_idx_to_addr(insn.get_next_dword()))
        if flags & FL.OP1_RULE_IDX_64:
            op_rule(insn.Op1, self.rule_idx_to_addr(insn.get_next_qword()))

        if flags & FL.OP1_REL_16:
            op_addr(insn.Op1, insn.ea + to_signed(insn.get_next_word(), 16))

        if flags & FL.OP1_REL_32:
            op_addr(insn.Op1, insn.ea + to_signed(insn.get_next_dword(), 32))

        if flags & FL.OP1_REL_64:
            op_addr(insn.Op1, insn.ea + to_signed(insn.get_next_qword(), 64))

        if flags & FL.OP1_ABS_64:
            op_addr(insn.Op1, insn.get_next_qword())

        if flags & FL.OP2_8:
            op_num(insn.Op2, insn.get_next_byte())

        if flags & FL.OP2_16:
            op_num(insn.Op2, insn.get_next_word())

        if flags & FL.OP2_32:
            op_num(insn.Op2, insn.get_next_dword())

        if flags & FL.OP2_RULE_IDX_32:
            op_rule(insn.Op2, self.rule_idx_to_addr(insn.get_next_dword()))

        if flags & FL.OP2_RULE_IDX_64:
            op_rule(insn.Op2, self.rule_idx_to_addr(insn.get_next_qword()))

        if flags & FL.OP2_64:
            op_num(insn.Op2, insn.get_next_qword())

        if flags & FL.OP2_REL_16:
            op_addr(insn.Op2, insn.ea + to_signed(insn.get_next_word(), 16))

        if flags & FL.OP2_REL_32:
            op_addr(insn.Op2, insn.ea + to_signed(insn.get_next_dword(), 32))

        if flags & FL.OP2_REL_64:
            op_addr(insn.Op2, insn.ea + to_signed(insn.get_next_qword(), 64))

        if flags & FL.OP3_8:
            op_num(insn.Op3, insn.get_next_byte())

        if flags & FL.OP3_16:
            op_num(insn.Op3, insn.get_next_word())

        if flags & FL.OP3_32:
            op_num(insn.Op3, insn.get_next_dword())

        if flags & FL.OP3_RULE_IDX_32:
            op_rule(insn.Op3, self.rule_idx_to_addr(insn.get_next_dword()))

        if flags & FL.OP3_RULE_IDX_64:
            op_rule(insn.Op3, self.rule_idx_to_addr(insn.get_next_qword()))

        if flags & FL.OP3_64:
            op_num(insn.Op3, insn.get_next_qword())

        if flags & FL.OP3_REL_16:
            op_addr(insn.Op3, insn.ea + to_signed(insn.get_next_word(), 16))

        if flags & FL.OP3_REL_32:
            op_addr(insn.Op3, insn.ea + to_signed(insn.get_next_dword(), 32))

        if flags & FL.OP3_REL_64:
            op_addr(insn.Op3, insn.ea + to_signed(insn.get_next_qword(), 64))

        if flags & FL.RE_CLASS:
            op_num(insn.Op1, insn.get_next_byte())
            # TODO: parse class
            class_ = [insn.get_next_byte() for _ in range(32)]
            # idaapi.set_cmt(insn.ea, class_to_str(class_), 0)

        return insn.size

    def ev_out_mnem(self, outctx):
        if outctx.insn.itype not in ITYPES:
            return 0
        outctx.out_custom_mnem(ITYPETODEF[outctx.insn.itype][1], MNEM_WIDTH)
        return 1

    # ----------------------------------------------------------------------
    def init_instructions(self):
        class idef:
            """
            Internal class that describes an instruction by:
            - instruction name
            - instruction decoding routine
            - canonical flags used by IDA
            """

            def __init__(self, name, cf, d, cmt=None):
                self.name = name
                self.cf = cf
                self.d = d
                self.cmt = cmt

        #
        # Instructions table (w/ pointer to decoder)
        #

        # Now create an instruction table compatible with IDA processor module requirements
        Instructions = [dict(name=f"dummy_{i}", feature=0) for i in range(256)]

        if 0:
            for x in OPCODES:
                # opcode, name, flags
                op = x[0]
                d = dict(name=x[1], feature=x[2])
                # if x.cmt != None:
                #    d['cmt'] = x.cmt
                Instructions[op] = d
                setattr(self, "itype_" + x[1], op)

        # icode of the last instruction + 1
        self.instruc_end = len(Instructions) + 1

        # Array of instructions
        self.instruc = Instructions

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = 0  # self.itype_OP_HALT

    # ----------------------------------------------------------------------
    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""

        # Registers definition
        self.reg_names = [
            # General purpose registers
            "SP",  # aka R0
            "R1",
            "R2",
            "R3",
            "R4",
            "R5",
            "R6",
            "R7",
            # VM registers
            "FLAGS",  # 0
            "IP",  # 1
            "VM2",
            "VM3",
            "VM4",
            "VM5",
            "VM6",
            "VM7",
            # Fake segment registers
            "CS",
            "DS",
        ]

        # Create the ireg_XXXX constants
        for i in range(len(self.reg_names)):
            setattr(self, "ireg_" + self.reg_names[i], i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg = self.ireg_DS

        # number of CS register
        self.reg_code_sreg = self.ireg_CS

        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    def update_rule_size(self):
        tif = idaapi.tinfo_t()
        if tif.parse("YR_RULE;"):
            self.rule_sz = tif.get_size()
        else:
            print("Failed to parse YR_RULE")
        seg = idaapi.get_segm_by_name("YR_RULES_TABLE")
        if seg:
            self.rules_ea = seg.start_ea

    # ----------------------------------------------------------------------
    def __init__(self):
        processor_t.__init__(self)
        self.PTRSZ = 8
        self.init_instructions()
        self.init_registers()
        self.rules_ea = idaapi.BADADDR
        self.rule_sz = 0


# ----------------------------------------------------------------------
def PROCESSOR_ENTRY():
    return yara_processor_t()


def op_addr(op: idaapi.op_t, dst: int):
    op.type = idaapi.o_near
    op.offb = 0x1
    op.offo = 0x0
    op.flags = 0x8
    op.dtype = idaapi.dt_qword
    op.reg = 0x0
    op.addr = dst
    op.specval = 0


def op_rule(op: idaapi.op_t, rule_addr: int):
    op.type = idaapi.o_mem
    op.offb = 0x1
    op.offo = 0x0
    op.flags = 0x8
    op.dtype = idaapi.dt_qword
    op.reg = 0x0
    op.addr = rule_addr
    op.specval = 0


def op_num(op: idaapi.op_t, n: int):
    op.type = idaapi.o_imm  # o_imm
    op.offb = 0x2
    op.offo = 0x0
    op.flags = 0x8
    op.dtype = idaapi.dt_qword
    op.value = n
