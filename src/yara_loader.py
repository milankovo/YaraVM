import idaapi
import idc
from enum import IntEnum

# -----------------------------------------------------------------------

# arena_id -> ea
arenas = {}


"""
// from compiler.h

#define YR_NAMESPACES_TABLE         0
#define YR_RULES_TABLE              1
#define YR_METAS_TABLE              2
#define YR_STRINGS_TABLE            3
#define YR_EXTERNAL_VARIABLES_TABLE 4
#define YR_SZ_POOL                  5
#define YR_CODE_SECTION             6
#define YR_RE_CODE_SECTION          7
#define YR_AC_TRANSITION_TABLE      8
#define YR_AC_STATE_MATCHES_TABLE   9
#define YR_AC_STATE_MATCHES_POOL    10
#define YR_SUMMARY_SECTION          11
"""


class ARENAS(IntEnum):
    YR_NAMESPACES_TABLE = 0
    YR_RULES_TABLE = 1
    YR_METAS_TABLE = 2
    YR_STRINGS_TABLE = 3
    YR_EXTERNAL_VARIABLES_TABLE = 4
    YR_SZ_POOL = 5
    YR_CODE_SECTION = 6
    YR_RE_CODE_SECTION = 7
    YR_AC_TRANSITION_TABLE = 8
    YR_AC_STATE_MATCHES_TABLE = 9
    YR_AC_STATE_MATCHES_POOL = 10
    YR_SUMMARY_SECTION = 11


arena_data_type_mapping = {
    ARENAS.YR_NAMESPACES_TABLE: "YR_NAMESPACE",
    ARENAS.YR_RULES_TABLE: "YR_RULE",
    ARENAS.YR_METAS_TABLE: "YR_META",
    ARENAS.YR_STRINGS_TABLE: "YR_STRING",
    ARENAS.YR_EXTERNAL_VARIABLES_TABLE: "YR_EXTERNAL_VARIABLE",
    ARENAS.YR_AC_TRANSITION_TABLE: "YR_AC_TRANSITION",
    ARENAS.YR_AC_STATE_MATCHES_TABLE: "uint32_t",  #  Table that translates from Aho-Corasick states (which are identified by numbers 0, 1, 2.. and so on) to the index in ac_match_pool where the YR_AC_MATCH structures for the corresponding state start. If the entry corresponding to state N in ac_match_table is zero, it means that there's no match associated to the state. If it's non-zero, its value is the 1-based index within ac_match_pool where the first match resides.
    ARENAS.YR_AC_STATE_MATCHES_POOL: "YR_AC_MATCH",
    ARENAS.YR_SUMMARY_SECTION: "YR_SUMMARY",
}


def accept_file(li: "idaapi.generic_linput_t", filename):
    if li.read(4) != b"YARA":
        return 0

    return {"format": "Compiled yara file", "processor": "yaravm"}  # accept the file


def addSegment(startea: int, endea: int, bitness: int, name: str, sclass: str):
    r"""
        @param sclass: (C++: const char *) class of the segment. may be nullptr. type of the new segment is
                   modified if class is one of predefined names:
    * "CODE" -> SEG_CODE
    * "DATA" -> SEG_DATA
    * "CONST" -> SEG_DATA
    * "STACK" -> SEG_BSS
    * "BSS" -> SEG_BSS
    * "XTRN" -> SEG_XTRN
    * "COMM" -> SEG_COMM
    * "ABS" -> SEG_ABSSYM


    @param bitness: (C++: size_t) new addressing mode of segment
    * 2: 64bit segment
    * 1: 32bit segment
    * 0: 16bit segment
    """

    s = idaapi.segment_t()
    s.start_ea = startea
    s.end_ea = endea
    s.bitness = bitness
    s.align = idaapi.saRelPara
    s.comb = idaapi.scPub
    idaapi.add_segm_ex(s, name, sclass, idaapi.ADDSEG_NOSREG | idaapi.ADDSEG_OR_DIE)


def REL_to_ea(idx, offset):
    seg = arenas.get(idx, None)
    assert seg is not None, f"Unknown arena: {idx}"
    return seg + offset


def read_relocation(offset):
    arena_id = idaapi.get_dword(offset)
    arena_offset = idaapi.get_dword(offset + 4)
    return arena_id, arena_offset


def relocate(ea: int):
    id, offset = read_relocation(ea)

    ea2 = REL_to_ea(id, offset)
    id2, offset2 = read_relocation(ea2)

    if id2 != idaapi.BADADDR32:
        ea3 = REL_to_ea(id2, offset2)
        idaapi.put_qword(ea2, ea3)


def apply_type(ea1: int, ea2: int, type_str: str, force_array=False):
    ti = idaapi.tinfo_t()
    assert ti.get_named_type(
        idaapi.cvar.idati, type_str
    ), f"apply_type: failed to get type {type_str}"
    available_space = ea2 - ea1

    ti_size = ti.get_size()

    ok = ti_size <= available_space

    assert ok, f"apply_type: not enough space for {type_str} at {hex(ea1)} {available_space=} {ti.get_size()=}"

    array_count = available_space // ti.get_size()

    if (array_count > 1) and (
        force_array or (ti_size <= 4) or (ea1 >= 0x000000001000000)
    ):
        ok = ti.create_array(ti, array_count)
        assert ok, f"apply_type: failed to create array of {array_count} {type_str}"
        return idaapi.apply_tinfo(ea1, ti, idaapi.TINFO_DEFINITE)

    for i in range(array_count):
        ok = idaapi.apply_tinfo(ea1 + i * ti.get_size(), ti, idaapi.TINFO_DEFINITE)
        assert ok, f"apply_type: failed to apply type {type_str} at {(ea1 + i * ti.get_size()):x}"
    return True


def apply_type_in_segment(name: str, type_str: str):
    seg: idaapi.segment_t = idaapi.get_segm_by_name(name)
    assert seg, f"apply_type_in_segment: segment {name} not found"
    apply_type(seg.start_ea, seg.end_ea, type_str)


# -----------------------------------------------------------------------
def load_file(li: idaapi.loader_input_t, neflags, format):
    # idaapi.set_processor_type("yaravm", idaapi.SETPROC_LOADER)
    idaapi.inf_set_app_bitness(64)

    # read header

    li.seek(5)

    arenas_count = int.from_bytes(li.read(1), byteorder="little")

    """
    struct __attribute__((packed)) __attribute__((aligned(4))) YR_ARENA_FILE_BUFFER
    {
       __int64 offset __offset(OFF64|AUTO);
        int size;
    };
    """

    # read arenas mapping

    header_size = 6 + 12 * arenas_count

    addSegment(0, 0 + header_size, 2, "Header", "CODE")
    li.file2base(0, 0, header_size, 1)

    segments = []
    segs_ea = 6
    for i in range(arenas_count):
        off = idaapi.get_qword(segs_ea)
        size = idaapi.get_dword(segs_ea + 8)
        segments.append((off, size))
        segs_ea += 12
    header_size = li.tell()

    # create segments for each arena

    # 0x1000000 is the first unmapped address
    unmapped_ea = 0x1000000

    relocations_start = 0
    for i, (off, size) in enumerate(segments):
        sclass = "DATA"
        if i in [ARENAS.YR_CODE_SECTION, ARENAS.YR_RE_CODE_SECTION]:
            sclass = "CODE"

        seg_ea = off
        seg_end = off + size

        if size == 0:
            seg_ea = unmapped_ea
            # arena.c:572, FAIL_ON_ERROR(yr_arena_create(hdr.num_buffers, 10485, &new_arena))
            seg_end = seg_ea + 10485
            unmapped_ea = seg_end

        addSegment(seg_ea, seg_end, 2, ARENAS(i).name, sclass)
        if size > 0:
            li.file2base(off, off, off + size, 1)

        arenas[i] = seg_ea
        relocations_start = max(relocations_start, off + size)

    # create a segment for relocations
    file_size = li.size()
    addSegment(relocations_start, file_size, 2, "Relocations", "CODE")
    li.file2base(relocations_start, relocations_start, file_size, 1)

    idc.add_default_til("libyara")

    # idaapi.inf_set_start_ip(arenas[ARENAS.YR_CODE_SECTION])

    idaapi.add_entry(0, arenas[ARENAS.YR_CODE_SECTION], "yara", 1)
    idaapi.add_entry(1, arenas[ARENAS.YR_RE_CODE_SECTION], "regex", 1)

    # create a segment for each code section
    # set the entry registers to F000:FFF0

    # apply relocations
    for i in range((file_size - relocations_start) // 8):
        relocate(relocations_start + 8 * i)

    # apply types
    idc.SetType(0, "YR_ARENA_FILE_HEADER h;")
    for i in range(arenas_count):
        idc.SetType(6 + i * 12, f"YR_ARENA_FILE_BUFFER seg{i};")
    apply_type(relocations_start, file_size, "YR_ARENA_REF", True)

    for k, v in arena_data_type_mapping.items():
        apply_type_in_segment(ARENAS(k).name, v)

    return 1


# -----------------------------------------------------------------------
def move_segm(frm, to, sz, fileformatname):
    idc.warning(
        "move_segm(from=%s, to=%s, sz=%d, formatname=%s"
        % (hex(frm), hex(to), sz, fileformatname)
    )
    return 0
