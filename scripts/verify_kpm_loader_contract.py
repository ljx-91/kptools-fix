#!/usr/bin/env python3
"""Fail-closed regression checks for the device and host KPM ELF parsers."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    brace = source.find("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:pos]
    raise AssertionError(f"unterminated function: {signature}")


def require(pattern, source, message):
    if not re.search(pattern, source, re.S):
        raise AssertionError(message)


def main():
    module = read("kernel/patch/module/module.c")
    relo = read("kernel/patch/module/relo.c")
    host = read("tools/kpm.c")

    header = function_body(module, "static int elf_header_check(")
    for token in ("EI_CLASS", "ELFCLASS64", "EI_DATA", "ELFDATA2LSB",
                  "e_ehsize", "e_shstrndx", "elf_range_valid"):
        require(re.escape(token), header, f"device ELF header check missing {token}")

    setup = function_body(module, "static int setup_load_info(")
    require(r"shstr->sh_type\s*!=\s*SHT_STRTAB", setup,
            "device parser must validate section-name table type")
    require(r"elf_string_valid\(info->secstrings", setup,
            "device parser must bound every section name")
    require(r"symsec->sh_entsize\s*!=\s*sizeof\(Elf_Sym\)", setup,
            "device parser must validate symbol entry size")
    require(r"symbols\[n\]\.st_name\s*>=", setup,
            "device parser must bound symbol string offsets")
    require(r"memchr\(info->strtab", setup,
            "device parser must require NUL-terminated symbol names")

    symbols = function_body(module, "static int simplify_symbols(")
    common_case = symbols[symbols.index("case SHN_COMMON"):symbols.index("case SHN_ABS")]
    require(r"ret\s*=\s*-ENOEXEC", common_case,
            "device loader must reject unsupported SHN_COMMON symbols")

    layout = function_body(module, "static int layout_sections(")
    require(r"get_offset\(", layout, "device layout must use checked offsets")
    require(r"section->sh_entsize\s*==\s*~0UL", layout,
            "device layout must reject unplaced alloc sections")
    move = function_body(module, "static int move_module(")
    require(r"shdr->sh_size\s*>\s*mod->size\s*-\s*shdr->sh_entsize", move,
            "device copy must bound section destination")

    reloc_dispatch = function_body(module, "static int apply_relocations(")
    require(r"target\s*>=\s*info->hdr->e_shnum", reloc_dispatch,
            "relocation target index must be bounded")
    require(r"relsec->sh_link\s*!=\s*info->index.sym", reloc_dispatch,
            "relocation symbol-table link must be checked")
    require(r"sh_type\s*==\s*SHT_REL\)\s*return\s*-ENOEXEC", reloc_dispatch,
            "unsupported REL must be rejected")
    require(r"sh_entsize\s*!=\s*sizeof\(Elf64_Rela\)", reloc_dispatch,
            "RELA entry size must be validated")

    data_reloc = function_body(relo, "static int reloc_data(")
    require(r"if\s*\(len\s*==\s*64\)\s*imm_mask\s*=\s*~0ULL", data_reloc,
            "64-bit relocation mask must avoid full-width shifts")
    require(r"1ULL\s*<<\s*len", data_reloc,
            "narrow relocation mask must use an unsigned 64-bit literal")
    require(r"op\s*==\s*RELOC_OP_PREL\s*&&\s*len\s*<\s*64", data_reloc,
            "PREL data relocations must enforce signed narrow ranges")
    require(r"return\s*-ERANGE", data_reloc,
            "data relocation overflow must fail")
    require(r"memcpy\(place,\s*&encoded,\s*sizeof\(encoded\)\)", data_reloc,
            "data relocations must use unaligned-safe writes")
    if re.search(r"\(1\s*<<\s*len\)", data_reloc):
        raise AssertionError("undefined 32-bit shift expression reintroduced")
    if data_reloc.find("return -ERANGE") > data_reloc.find("memcpy(place,"):
        raise AssertionError("data relocation must validate overflow before writing")

    movw = function_body(relo, "static int reloc_insn_movw(")
    require(r"if\s*\(sval\s*>=\s*0\).*?imm\s*=\s*~imm", movw,
            "signed MOVW must select MOVZ/MOVN from the full signed value")
    if "(s64)imm >= 0" in movw:
        raise AssertionError("signed MOVW selector must not inspect the truncated immediate")

    rela = function_body(relo, "int apply_relocate_add(")
    require(r"symno\s*>=\s*symhdr->sh_size\s*/\s*sizeof\(Elf64_Sym\)", rela,
            "RELA symbol index must be bounded")
    require(r"r_offset\s*>\s*targethdr->sh_size", rela,
            "RELA target offset must be bounded")
    require(r"width\s*>\s*targethdr->sh_size\s*-\s*rel\[i\]\.r_offset", rela,
            "RELA write width must fit target section")
    require(r"type\s*!=\s*R_AARCH64_ABS32.*?type\s*!=\s*R_AARCH64_PREL32.*?type\s*!=\s*R_AARCH64_ABS16.*?type\s*!=\s*R_AARCH64_PREL16",
            rela, "RELA alignment checks must exempt packed data relocations")
    if "rel[i].r_offset & (width - 1)" in rela:
        raise AssertionError("data relocations must not be forced to natural alignment")
    require(r"backup\s*=\s*vmalloc\(targethdr->sh_size", rela,
            "RELA application must snapshot the target section before writing")
    require(r"memcpy\(backup,\s*\(void \*\)targethdr->sh_addr", rela,
            "RELA transaction must save original target bytes")
    require(r"goto rollback", rela,
            "late relocation errors must enter transaction rollback")
    require(r"memcpy\(\(void \*\)targethdr->sh_addr,\s*backup", rela,
            "RELA rollback must restore the complete target section")
    require(r"vfree\(backup\)", rela,
            "RELA transaction must release its snapshot")


    require(r"int apply_relocate\([\s\S]*?return\s*-ENOEXEC", relo,
            "unsupported REL helper must fail closed")

    unload = function_body(module, "long unload_module(")
    require(r"if\s*\(mod->exit\)\s*rc\s*=", unload,
            "optional KPM exit callback must be checked before invocation")
    require(r"KP_MODULE_EXITING\s*&&\s*!mod->exit_called", unload,
            "concurrent unload must not invoke the exit callback twice")

    host_header = function_body(host, "int get_kpm_info(")
    for token in ("EI_CLASS", "e_shstrndx", "elf_range_valid",
                  "SHT_STRTAB", "elf_string_valid"):
        require(re.escape(token), host_header, f"host KPM parser missing {token}")
    require(r"return infosec->sh_size;", host,
            "host .kpm.info size must use sh_size")
    require(r"return infosec->sh_size;", module,
            "device .kpm.info size must use sh_size")

    print("[PASS] device ELF header, section and symbol bounds")
    print("[PASS] checked KPM section layout and destination copies")
    print("[PASS] RELA metadata, symbol index and target write bounds")
    print("[PASS] unsupported AArch64 REL fails closed")
    print("[PASS] 64-bit relocation mask avoids undefined shifts")
    print("[PASS] host KPM metadata parser validates ELF ranges and strings")
    print("[PASS] .kpm.info reports sh_size, not sh_entsize")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
