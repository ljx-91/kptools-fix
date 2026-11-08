#!/usr/bin/env python3
"""Fail-closed source checks for the separate LKM KPM ELF loader."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def body(source, signature):
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


def need(pattern, source, message):
    if not re.search(pattern, source, re.S):
        raise AssertionError(message)


def main():
    module = read("lkm/kpm/module.c")
    relo = read("lkm/kpm/relo.c")

    header = body(module, "static int elf_header_check(")
    for token in ("ELFCLASS64", "ELFDATA2LSB", "EI_VERSION",
                  "e_ehsize", "e_shentsize", "e_shstrndx",
                  "kp_elf_range_valid"):
        need(re.escape(token), header, f"ELF header validation missing {token}")

    ranges = body(module, "static int rewrite_section_headers(")
    need(r"shstr->sh_type\s*!=\s*SHT_STRTAB", ranges, "section-name table type")
    need(r"kp_elf_range_valid\(info->len", ranges, "section file extent bounds")
    need(r"kp_elf_string_valid\(info->secstrings", ranges, "section name termination")
    need(r"sh_addralign.*sh_addralign\s*-\s*1", ranges, "section alignment")

    setup = body(module, "static int setup_load_info(")
    for pattern, message in [
        (r"symsec->sh_entsize\s*!=\s*sizeof\(Elf_Sym\)", "symbol entry size"),
        (r"symsec->sh_link\s*>=\s*info->hdr->e_shnum", "symbol string-table index"),
        (r"strsec->sh_type\s*!=\s*SHT_STRTAB", "symbol string-table type"),
        (r"kp_elf_string_valid\(info->strtab", "symbol name bounds"),
        (r"st_shndx\s*==\s*SHN_XINDEX", "extended symbol index rejection"),
        (r"info->info.base\[info->info.size\s*-\s*1\]\s*!=\s*'\\0'", ".kpm.info termination"),
    ]:
        need(pattern, setup, f"setup_load_info must validate {message}")

    layout = body(module, "static int layout_sections(")
    need(r"get_offset\(", layout, "checked section reservation")
    need(r"kp_align_module_size\(", layout, "checked page alignment")
    sym_layout = body(module, "static int layout_symtab(")
    need(r"UINT_MAX\s*-\s*info->symoffs", sym_layout, "symbol table extent")
    need(r"UINT_MAX\s*-\s*info->stroffs", sym_layout, "string table extent")

    move = body(module, "static int move_module(")
    need(r"shdr->sh_entsize\s*>\s*mod->size", move, "destination offset")
    need(r"shdr->sh_size\s*>\s*mod->size\s*-\s*shdr->sh_entsize", move, "destination section extent")

    dispatch = body(module, "static int apply_relocations(")
    need(r"infosec\s*>=\s*info->hdr->e_shnum", dispatch, "relocation target index")
    need(r"sh_link\s*!=\s*info->index.sym", dispatch, "relocation symbol-table link")

    load = body(module, "long kp_load_module(")
    need(r"len\s*<=\s*0", load, "non-positive in-memory image length")
    path_load = body(module, "long kp_load_module_path(")
    need(r"len\s*<=\s*0\s*\|\|\s*len\s*>\s*INT_MAX", path_load,
         "oversized on-disk image length")

    trampoline = body(module, "int kp_kpm_safe_kallsyms_on_each_symbol(")
    need(r"kp_callback_tramp_slot_alloc", trampoline, "exclusive callback trampoline slot")
    need(r"branch_off\s*>=\s*\(1L\s*<<\s*27\)", trampoline,
         "AArch64 branch immediate range check")
    need(r"kp_callback_tramp_slot_free\(slot\)", trampoline,
         "callback trampoline slot release")

    data = body(relo, "static int reloc_data(")
    need(r"len\s*==\s*64", data, "explicit 64-bit relocation width")
    need(r"1ULL\s*<<\s*len", data, "unsigned 64-bit narrow mask")
    if re.search(r"\(1\s*<<\s*len\)", data):
        raise AssertionError("undefined 32-bit full-width shift reintroduced")

    rela = body(relo, "int kp_apply_relocate_add(")
    for pattern, message in [
        (r"rsec->sh_type\s*!=\s*SHT_RELA", "RELA section type"),
        (r"rsec->sh_entsize\s*!=\s*sizeof\(Elf64_Rela\)", "RELA entry size"),
        (r"symidx\s*>=\s*nsym", "RELA symbol index"),
        (r"rel\[i\]\.r_offset\s*>\s*target->sh_size", "RELA target offset"),
        (r"width\s*>\s*target->sh_size\s*-\s*rel\[i\]\.r_offset", "RELA write extent"),
    ]:
        need(pattern, rela, f"RELA loader must validate {message}")

    rel = body(relo, "int kp_apply_relocate(")
    need(r"return\s*-EOPNOTSUPP", rel, "unimplemented REL must fail closed")

    print("[PASS] LKM ELF64 header, section table and string bounds")
    print("[PASS] LKM symbol table, names and section indexes")
    print("[PASS] LKM checked section layout and destination copy extents")
    print("[PASS] LKM RELA metadata, symbol and target bounds")
    print("[PASS] LKM input-size and concurrent callback trampoline guards")
    print("[PASS] unimplemented REL fails closed")
    print("[PASS] 64-bit relocation mask avoids undefined shifts")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
