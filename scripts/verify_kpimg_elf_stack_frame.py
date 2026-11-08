#!/usr/bin/env python3
"""Verify the exact AArch64 stack-frame contract used by the Y73S KPIMG tail handoff."""
from pathlib import Path
import hashlib
import struct
import sys

# AArch64 64-bit STP encodings used by GCC:
#   offset:   STP Xt, Xt2, [SP, #imm]
#   preindex: STP Xt, Xt2, [SP, #-frame]!
STP_X_OFFSET_MASK = 0xFFC00000
STP_X_OFFSET = 0xA9000000
STP_X_PREINDEX = 0xA9800000
MOV_FP_SP_MASK = 0xFFC003FF
MOV_FP_SP = 0x910003FD
RESTORE = [
    0xF94003AA, 0xA9415153, 0xA9425955, 0xA9436157,
    0xA9446959, 0xA945715B, 0xF940015D, 0xF940055E,
]
RET = 0xD65F03C0
EXPECTED_FRAME_SIZE = 0x130
EXPECTED_SAVES = {
    (19, 20): 0x10,
    (21, 22): 0x20,
    (23, 24): 0x30,
    (25, 26): 0x40,
    (27, 28): 0x50,
}


def cstr(blob, offset):
    end = blob.find(b"\\0", offset)
    if end < 0:
        raise ValueError("unterminated ELF string")
    return blob[offset:end].decode("utf-8", "replace")


def load_elf(path):
    blob = Path(path).read_bytes()
    if len(blob) < 64 or blob[:4] != b"\\x7fELF":
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


def sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode_stp_x(word):
    """Return (mode, rt, rt2, rn, byte_offset) for 64-bit GPR STP, else None."""
    masked = word & STP_X_OFFSET_MASK
    if masked == STP_X_OFFSET:
        mode = "offset"
    elif masked == STP_X_PREINDEX:
        mode = "preindex"
    else:
        return None
    imm7 = sign_extend((word >> 15) & 0x7F, 7)
    return mode, word & 0x1F, (word >> 10) & 0x1F, (word >> 5) & 0x1F, imm7 * 8


def is_call(word):
    # BL immediate or BLR Xn.
    return (word & 0xFC000000) == 0x94000000 or (word & 0xFFFFFC1F) == 0xD63F0000


def main(path):
    blob, symbols = load_elf(path)
    for name in ("_paging_init", "start"):
        if len(symbols.get(name, [])) != 1:
            raise ValueError(f"expected one defined {name} function, got {len(symbols.get(name, []))}")

    paging = symbols["_paging_init"][0]
    start = symbols["start"][0]
    pw = words_for(blob, paging)
    sw = words_for(blob, start)

    # _paging_init must establish the exact frame pointer used by start's inline
    # assembly. The tail code hardcodes 0x130, so any other frame is incompatible.
    if len(pw) < 2:
        raise ValueError("_paging_init is too short to contain its frame prologue")
    first = decode_stp_x(pw[0])
    if first != ("preindex", 29, 30, 31, -EXPECTED_FRAME_SIZE):
        raise ValueError("_paging_init does not save x29/x30 with the expected 0x130-byte SP frame")
    if (pw[1] & MOV_FP_SP_MASK) != MOV_FP_SP:
        raise ValueError("_paging_init does not establish x29 = SP immediately after its frame save")

    frame_size = -first[4]
    if frame_size != EXPECTED_FRAME_SIZE:
        raise ValueError(f"_paging_init frame changed: expected 0x{EXPECTED_FRAME_SIZE:x}, got 0x{frame_size:x}")

    # Verify every callee-saved register pair at the precise offsets consumed
    # by start's tail-return assembly. A frame-size-only check is insufficient.
    observed = {}
    first_call = next((i for i, w in enumerate(pw) if is_call(w)), len(pw))
    for i, word in enumerate(pw):
        decoded = decode_stp_x(word)
        if not decoded:
            continue
        mode, rt, rt2, rn, offset = decoded
        if mode == "offset" and rn == 31 and (rt, rt2) in EXPECTED_SAVES:
            observed.setdefault((rt, rt2), []).append((offset, i))
    for pair, expected_offset in EXPECTED_SAVES.items():
        entries = observed.get(pair, [])
        if len(entries) != 1:
            raise ValueError(f"_paging_init must save x{pair[0]}/x{pair[1]} exactly once; found {entries}")
        actual_offset, insn_index = entries[0]
        if actual_offset != expected_offset:
            raise ValueError(
                f"_paging_init saves x{pair[0]}/x{pair[1]} at 0x{actual_offset:x}, "
                f"but start restores from 0x{expected_offset:x}"
            )
        if insn_index >= first_call:
            raise ValueError(f"_paging_init saves x{pair[0]}/x{pair[1]} after its first call")

    # The caller's frame record must be established by start before any call.
    start_frame_records = []
    start_fp_sets = []
    for i, word in enumerate(sw[:8]):
        decoded = decode_stp_x(word)
        if decoded and decoded[0] == "preindex" and decoded[1:4] == (29, 30, 31):
            start_frame_records.append((i, decoded[4]))
        if (word & MOV_FP_SP_MASK) == MOV_FP_SP:
            start_fp_sets.append(i)
    if len(start_frame_records) != 1 or len(start_fp_sets) != 1:
        raise ValueError("start entry does not uniquely establish its x29/x30 frame record")
    if start_frame_records[0][0] >= start_fp_sets[0]:
        raise ValueError("start establishes x29 before saving its frame record")
    if any(is_call(w) for w in sw[:start_fp_sets[0]]):
        raise ValueError("start calls another function before establishing x29")

    # Match the exact handoff sequence and reject ambiguous duplicate tails.
    restore_candidates = []
    for i in range(len(sw) - len(RESTORE) - 1):
        if sw[i:i + len(RESTORE)] != RESTORE:
            continue
        add_sp = sw[i + len(RESTORE)]
        if sw[i + len(RESTORE) + 1] != RET:
            continue
        if (add_sp & 0xFFC003FF) != 0x9100015F or ((add_sp >> 22) & 1):
            continue
        restore_candidates.append((i, (add_sp >> 10) & 0xFFF))
    if len(restore_candidates) != 1:
        raise ValueError(f"start restore pattern missing/ambiguous: {restore_candidates}")
    _, actual_sp = restore_candidates[0]
    if actual_sp != frame_size:
        raise ValueError(f"SP restore mismatch: expected 0x{frame_size:x}, actual 0x{actual_sp:x}")

    print(f"SHA256: {hashlib.sha256(blob).hexdigest()}")
    print(f"_paging_init: 0x{paging['value']:x} size=0x{paging['size']:x} section={paging['section']}")
    print(f"start:         0x{start['value']:x} size=0x{start['size']:x} section={start['section']}")
    print(f"frame: 0x{frame_size:x}; verified x19-x28 save slots: " +
          ", ".join(f"x{a}/x{b}@0x{off:x}" for (a, b), off in EXPECTED_SAVES.items()))
    print(f"start tail SP restore: 0x{actual_sp:x}")
    print("[PASS] exact Y73S stack handoff contract verified")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: verify_kpimg_elf_stack_frame.py kpimg.elf")
        main(sys.argv[1])
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(2)
