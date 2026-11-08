#!/usr/bin/env python3
"""ELF-symbol-scoped verifier for the Y73S KPIMG stack handoff."""
from pathlib import Path
import hashlib
import struct
import sys

# GCC 14.2 Y73S build: stp x29, x30, [sp, #-frame]!, then mov x29, sp.
# The immediate is the signed 7-bit STP pair offset, scaled by 8.
STP_FP_LR_PREINDEX_MASK = 0xFFC07FFF
STP_FP_LR_PREINDEX = 0xA9807BFD
MOV_FP_SP = 0x910003FD
RESTORE = [
    0xF94003AA, 0xA9415153, 0xA9425955, 0xA9436157,
    0xA9446959, 0xA945715B, 0xF940015D, 0xF940055E,
]
RET = 0xD65F03C0


def cstr(blob, offset):
    end = blob.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated ELF string")
    return blob[offset:end].decode("utf-8", "replace")


def load_elf(path):
    blob = Path(path).read_bytes()
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise ValueError("input is not an ELF file")
    if blob[4] != 2 or blob[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", blob, 0)
    machine, shoff, shentsize, shnum, shstrndx = hdr[2], hdr[6], hdr[11], hdr[12], hdr[13]
    if machine != 183:
        raise ValueError(f"expected AArch64 ELF (e_machine=183), got {machine}")
    if shentsize < 64 or not shnum or shstrndx >= shnum:
        raise ValueError("invalid ELF section table")

    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        if off + 64 > len(blob):
            raise ValueError("section header outside ELF")
        sh = struct.unpack_from("<IIQQQQIIQQ", blob, off)
        sections.append({
            "name_off": sh[0], "type": sh[1], "addr": sh[3],
            "offset": sh[4], "size": sh[5], "link": sh[6],
            "entsize": sh[9],
        })
    shstr = sections[shstrndx]
    names = blob[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for sec in sections:
        sec["name"] = cstr(names, sec["name_off"])

    symbols = {}
    for sec in sections:
        if sec["type"] != 2:  # SHT_SYMTAB
            continue
        if sec["link"] >= len(sections):
            raise ValueError("invalid symtab string-table link")
        strings_sec = sections[sec["link"]]
        strings = blob[strings_sec["offset"]:strings_sec["offset"] + strings_sec["size"]]
        ent = sec["entsize"] or 24
        if ent < 24:
            raise ValueError("invalid ELF64 symbol entry size")
        for pos in range(sec["offset"], sec["offset"] + sec["size"], ent):
            if pos + 24 > len(blob):
                raise ValueError("symbol outside ELF")
            name_off, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", blob, pos)
            if not name_off:
                continue
            name = cstr(strings, name_off)
            if name in ("_paging_init", "start") and (info & 0x0F) == 2 and shndx < len(sections):
                s = sections[shndx]
                if s["type"] == 8:  # SHT_NOBITS
                    continue
                file_off = s["offset"] + (value - s["addr"])
                if value < s["addr"] or file_off + size > len(blob):
                    raise ValueError(f"symbol {name} has invalid section bounds")
                symbols.setdefault(name, []).append({
                    "value": value, "size": size, "file_off": file_off,
                    "section": s["name"],
                })
    return blob, symbols


def words_for(blob, sym):
    if sym["size"] < 4 or sym["size"] % 4:
        raise ValueError(f"{sym['section']} symbol size is not instruction aligned")
    n = sym["size"] // 4
    return list(struct.unpack_from("<" + "I" * n, blob, sym["file_off"]))


def main(path):
    blob, symbols = load_elf(path)
    for name in ("_paging_init", "start"):
        if len(symbols.get(name, [])) != 1:
            raise ValueError(f"expected one defined {name} function, got {len(symbols.get(name, []))}")

    paging = symbols["_paging_init"][0]
    start = symbols["start"][0]
    pw = words_for(blob, paging)
    sw = words_for(blob, start)

    if len(pw) < 2 or (pw[0] & STP_FP_LR_PREINDEX_MASK) != STP_FP_LR_PREINDEX:
        raise ValueError("_paging_init does not begin with the expected FP/LR pre-index save")
    if pw[1] != MOV_FP_SP:
        raise ValueError("_paging_init does not establish x29 = SP immediately after its frame save")

    imm7 = (pw[0] >> 15) & 0x7F
    if imm7 & 0x40:
        imm7 -= 0x80
    frame_size = -imm7 * 8
    fp_offset = 0
    if frame_size < 96 or frame_size % 16:
        raise ValueError(f"implausible _paging_init frame size: 0x{frame_size:x}")
    expected_sp = frame_size - fp_offset

    # Confirm start saves a frame record and establishes x29 before its tail return.
    saves_fp_lr = any((w & 0xFFC07FFF) in (0xA9007BFD, 0xA9807BFD) for w in sw[:8])
    sets_fp = any((w & 0xFFC003FF) == 0x910003FD for w in sw[:8])
    if not saves_fp_lr or not sets_fp:
        raise ValueError("start entry does not establish a saved x29/x30 frame record")

    restore_candidates = []
    for i in range(len(sw) - len(RESTORE) - 1):
        if sw[i:i + len(RESTORE)] != RESTORE:
            continue
        add_sp = sw[i + len(RESTORE)]
        if sw[i + len(RESTORE) + 1] != RET:
            continue
        if (add_sp & 0xFFC003FF) != 0x9100015F or ((add_sp >> 22) & 1):
            continue
        restore_candidates.append((add_sp >> 10) & 0xFFF)
    if len(restore_candidates) != 1:
        raise ValueError(f"start restore pattern missing/ambiguous: {restore_candidates}")
    actual_sp = restore_candidates[0]

    print(f"SHA256: {hashlib.sha256(blob).hexdigest()}")
    print(f"_paging_init: 0x{paging['value']:x} size=0x{paging['size']:x} section={paging['section']}")
    print(f"start:         0x{start['value']:x} size=0x{start['size']:x} section={start['section']}")
    print(f"GCC frame=0x{frame_size:x}; FP offset=0x{fp_offset:x}; expected SP restore=0x{expected_sp:x}; actual=0x{actual_sp:x}")
    if actual_sp != expected_sp:
        raise ValueError("SP restore mismatch; refusing KPIMG artifact")
    print("[PASS] ELF-symbol-scoped Y73S stack handoff verifier")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: verify_kpimg_elf_stack_frame.py kpimg.elf")
        main(sys.argv[1])
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(2)
