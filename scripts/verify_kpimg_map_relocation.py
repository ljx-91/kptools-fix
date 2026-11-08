#!/usr/bin/env python3
"""Fail closed if copied Y73S .setup.map code branches outside its own section."""
from pathlib import Path
import struct
import sys

SHT_SYMTAB = 2
SHT_NOBITS = 8
STT_FUNC = 2
MAP_SECTION = ".setup.map"
MAP_MAX_SIZE = 0x1000


def sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def parse_elf(path):
    blob = Path(path).read_bytes()
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise ValueError("input is not ELF")
    if blob[4] != 2 or blob[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", blob, 0)
    if hdr[2] != 183:
        raise ValueError("expected AArch64 ELF")
    shoff, shentsize, shnum, shstrndx = hdr[6], hdr[11], hdr[12], hdr[13]
    if shentsize < 64 or not shnum or shstrndx >= shnum:
        raise ValueError("invalid section table")
    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        if off + 64 > len(blob):
            raise ValueError("section header outside file")
        sh = struct.unpack_from("<IIQQQQIIQQ", blob, off)
        sections.append({"name_off": sh[0], "type": sh[1], "addr": sh[3],
                         "offset": sh[4], "size": sh[5], "link": sh[6],
                         "entsize": sh[9]})
    shstr = sections[shstrndx]
    names = blob[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for sec in sections:
        end = names.find(b"\0", sec["name_off"])
        if end < 0:
            raise ValueError("bad section-name string")
        sec["name"] = names[sec["name_off"]:end].decode("ascii", "replace")
    maps = [s for s in sections if s["name"] == MAP_SECTION]
    if len(maps) != 1:
        raise ValueError(f"expected one {MAP_SECTION}, found {len(maps)}")
    m = maps[0]
    if m["type"] == SHT_NOBITS or not m["size"] or m["size"] > MAP_MAX_SIZE:
        raise ValueError(f"{MAP_SECTION} size/type invalid: 0x{m['size']:x}")
    if m["offset"] + m["size"] > len(blob):
        raise ValueError(f"{MAP_SECTION} outside ELF")
    funcs = []
    for sec in sections:
        if sec["type"] != SHT_SYMTAB:
            continue
        if sec["link"] >= len(sections):
            raise ValueError("bad symtab string table")
        st = sections[sec["link"]]
        strings = blob[st["offset"]:st["offset"] + st["size"]]
        ent = sec["entsize"] or 24
        if ent < 24:
            raise ValueError("bad symbol entry size")
        for pos in range(sec["offset"], sec["offset"] + sec["size"], ent):
            if pos + 24 > len(blob):
                raise ValueError("symbol outside ELF")
            no, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", blob, pos)
            if not no or (info & 0x0f) != STT_FUNC or shndx >= len(sections):
                continue
            if sections[shndx]["name"] != MAP_SECTION or not size:
                continue
            if value < m["addr"] or value + size > m["addr"] + m["size"]:
                raise ValueError("function symbol escapes .setup.map")
            funcs.append((value, size))
    if not funcs:
        raise ValueError("no function symbols found in .setup.map")
    return blob, m, funcs


def branch_target(word, pc):
    # B / BL: imm26, scaled by four.
    if (word & 0x7C000000) == 0x14000000:
        return pc + (sign_extend(word & 0x03FFFFFF, 26) << 2)
    # B.cond and CBZ/CBNZ: imm19, scaled by four.
    if (word & 0xFF000010) == 0x54000000 or (word & 0x7E000000) == 0x34000000:
        return pc + (sign_extend((word >> 5) & 0x7FFFF, 19) << 2)
    # TBZ/TBNZ: imm14, scaled by four.
    if (word & 0x7E000000) == 0x36000000:
        return pc + (sign_extend((word >> 5) & 0x3FFF, 14) << 2)
    return None


def pc_relative_reference(word, pc):
    # ADR / ADRP use a signed 21-bit immediate split across immhi/immlo.
    op = word & 0x9F000000
    if op in (0x10000000, 0x90000000):
        imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
        imm = sign_extend(imm, 21)
        if op == 0x10000000:
            return ("ADR", pc + imm)
        return ("ADRP", (pc & ~0xFFF) + (imm << 12))
    # LDR (literal), LDRSW (literal), PRFM (literal), and SIMD literal loads.
    if (word & 0x3B000000) == 0x18000000:
        target = pc + (sign_extend((word >> 5) & 0x7FFFF, 19) << 2)
        return ("LDR-literal", target)
    return None


def main(path):
    blob, sec, funcs = parse_elf(path)
    lo, hi = sec["addr"], sec["addr"] + sec["size"]
    checked = 0
    bad = []
    refs_checked = 0
    bad_refs = []
    for value, size in funcs:
        off = sec["offset"] + (value - lo)
        for i in range(0, size - 3, 4):
            word = struct.unpack_from("<I", blob, off + i)[0]
            pc = value + i
            target = branch_target(word, pc)
            if target is not None:
                checked += 1
                if not lo <= target < hi:
                    bad.append((pc, target, word))
            ref = pc_relative_reference(word, pc)
            if ref is not None:
                kind, target = ref
                refs_checked += 1
                if kind == "ADRP":
                    # ADRP names a page base; the actual ADD/load offset is
                    # checked by requiring that page to overlap .setup.map.
                    valid = target < hi and target + 0x1000 > lo
                else:
                    valid = lo <= target < hi
                if not valid:
                    bad_refs.append((pc, target, word, kind))
    print(f".setup.map size=0x{sec['size']:x}; function_symbols={len(funcs)}; "
          f"direct_branches_checked={checked}; pc_relative_refs_checked={refs_checked}")
    if bad:
        for pc, target, word in bad[:20]:
            print(f"external branch: pc=0x{pc:x} insn=0x{word:08x} target=0x{target:x}")
        raise ValueError(f"{len(bad)} direct branch(es) leave copied .setup.map")
    if bad_refs:
        for pc, target, word, kind in bad_refs[:20]:
            print(f"external {kind}: pc=0x{pc:x} insn=0x{word:08x} target=0x{target:x}")
        raise ValueError(f"{len(bad_refs)} PC-relative reference(s) leave copied .setup.map")
    print("[PASS] copied .setup.map direct branches and PC-relative references stay inside the copied section")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: verify_kpimg_map_relocation.py kpimg.elf")
        main(sys.argv[1])
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(2)
